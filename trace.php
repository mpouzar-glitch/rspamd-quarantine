<?php
/**
 * Message Trace - Full Email Traffic Log
 * Displays all messages processed by Rspamd (not just quarantined)
 */

require_once 'config.php';
require_once 'filter_helper.php';
require_once 'lang_helper.php';

// Check authentication
if (!isAuthenticated()) {
    header('Location: login.php');
    exit;
}

$db = Database::getInstance()->getConnection();
$userRole = $_SESSION['user_role'] ?? 'viewer';
$user = $_SESSION['username'] ?? 'unknown';
$returnUrl = $_SERVER['REQUEST_URI'] ?? 'trace.php';
$canManageMaps = checkPermission('domain_admin');

// Get filters from request
$filters = getTraceFiltersFromRequest();

// Reset pagination
$resetPage = isset($_GET['reset_page']) && $_GET['reset_page'] == '1';

// Sorting
$sortableColumns = [
    'timestamp' => 'timestamp',
    'sender' => 'sender',
    'recipients' => 'recipients',
    'subject' => 'subject',
    'action' => 'action',
    'score' => 'score',
    'ip_address' => 'ip_address',
    'hostname' => 'hostname',
];
$sort = $_GET['sort'] ?? 'timestamp';
$sortDir = strtolower($_GET['dir'] ?? 'desc');
if (!isset($sortableColumns[$sort])) {
    $sort = 'timestamp';
}
$sortDir = $sortDir === 'asc' ? 'asc' : 'desc';
$orderBy = $sortableColumns[$sort] . ' ' . strtoupper($sortDir);
$sortParams = array_diff_key($_GET, ['page' => '', 'sort' => '', 'dir' => '', 'reset_page' => '']);
$buildSortLink = function (string $column) use ($sort, $sortDir, $sortParams): string {
    $nextDir = ($sort === $column && $sortDir === 'asc') ? 'desc' : 'asc';
    $params = array_merge($sortParams, [
        'sort' => $column,
        'dir' => $nextDir,
        'page' => 1,
    ]);
    return '?' . http_build_query($params);
};
$getSortIcon = function (string $column) use ($sort, $sortDir): string {
    if ($sort !== $column) {
        return 'fa-sort';
    }
    return $sortDir === 'asc' ? 'fa-sort-up' : 'fa-sort-down';
};

// Pagination
$page = $resetPage ? 1 : (isset($_GET['page']) ? max(1, (int)$_GET['page']) : 1);
$offset = ($page - 1) * ITEMS_PER_PAGE;

// Get total count
$totalItems = countTraceMessages($db, $filters);
$totalPages = max(1, (int)ceil($totalItems / ITEMS_PER_PAGE));

// Build and execute query
$params = [];
$sql = buildTraceQuery($filters, $params, [
    'limit' => ITEMS_PER_PAGE,
    'offset' => $offset,
    'order_by' => $orderBy,
]);

$stmt = $db->prepare($sql);
$stmt->execute($params);
$messages = $stmt->fetchAll(PDO::FETCH_ASSOC);

$listedEmails = ['whitelist' => [], 'blacklist' => []];
if ($canManageMaps && !empty($messages)) {
    $senderEmails = [];
    foreach ($messages as $message) {
        $senderEmail = extractEmailAddress(decodeMimeHeader($message['sender']));
        if (!empty($senderEmail)) {
            $senderEmails[] = $senderEmail;
        }
    }
    $listedEmails = getEmailMapStatus($db, $senderEmails);
}

// Get statistics
$stats = getTraceStats($db, $filters);

$page_title = __('trace_page_title', ['app' => __('app_title')]);
include 'menu.php';
?>

<!DOCTYPE html>
<html lang="<?php echo htmlspecialchars(currentLang()); ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($page_title); ?></title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link rel="stylesheet" href="css/stats-inline.css">
    <link rel="stylesheet" href="css/style.css">
    <link rel="stylesheet" href="css/bulk.css">
</head>
<body>
    <div class="container">
        <!-- HEADER WITH STATISTICS -->
        <div class="header-with-stats">
            <div class="header-title">
            <h1><i class="fas fa-route"></i> <?php echo htmlspecialchars(__('trace_title')); ?></h1>
        </div>
            <div>
                <?php
                echo renderStatsInline($stats, [
                    'show_total' => true,
                    'show_rejected' => true,
                    'show_marked' => true,
                    'show_passed' => true,
                    'show_avg_score' => true,
                    'show_max_score' => true,
                    'show_min_score' => true,
                ]);
                ?>
            </div>
        </div>

        <?php displayAlerts(); ?>

        <!-- FILTERS -->
        <?php
        echo renderSearchFilters(getQuarantineFilters([
            'columns' => null,
            'show_search' => true,
            'show_action' => true,
            'show_score_min' => false,
            'show_score_max' => false,
            'show_dates' => true,
            'show_sender' => true,
            'show_recipient' => true,
            'show_state' => false,
            'show_ip' => ($filters['ip'] ?? false),
            'show_auth_user' => false,
            'form_id' => 'filterForm',
            'reset_url' => 'trace.php',
        ]));
        ?>

        <!-- Results Info -->
        <div class="results-info">
            <div class="results-text">
                <i class="fas fa-info-circle"></i>
                <?php echo __(
                    'trace_results_info',
                    [
                        'shown' => number_format(count($messages)),
                        'total' => number_format($totalItems),
                    ]
                ); ?>
                <?php if (!empty(array_filter($filters))): ?>
                    (<?php echo htmlspecialchars(__('trace_filtered')); ?>)
                <?php endif; ?>
            </div>
        </div>

        <!-- Messages Table -->
        <?php if (empty($messages)): ?>
            <div class="empty-state">
                <i class="fas fa-inbox"></i>
                <h3><?php echo htmlspecialchars(__('trace_no_messages_title')); ?></h3>
                <p><?php echo htmlspecialchars(__('trace_no_messages_desc')); ?></p>
            </div>
        <?php else: ?>
            <div class="table-container">
                <table class="messages-table">
                    <thead>
                        <tr>
                            <th class="col-timestamp">
                                <a class="sort-link <?php echo $sort === 'timestamp' ? 'active' : ''; ?>" href="<?php echo $buildSortLink('timestamp'); ?>">
                                    <?php echo htmlspecialchars(__('time')); ?>
                                    <i class="fas <?php echo $getSortIcon('timestamp'); ?>"></i>
                                </a>
                            </th>
                            <th class="col-email">
                                <a class="sort-link <?php echo $sort === 'sender' ? 'active' : ''; ?>" href="<?php echo $buildSortLink('sender'); ?>">
                                    <?php echo htmlspecialchars(__('msg_sender')); ?>
                                    <i class="fas <?php echo $getSortIcon('sender'); ?>"></i>
                                </a>
                            </th>
                            <th class="col-email">
                                <a class="sort-link <?php echo $sort === 'recipients' ? 'active' : ''; ?>" href="<?php echo $buildSortLink('recipients'); ?>">
                                    <?php echo htmlspecialchars(__('msg_recipient')); ?>
                                    <i class="fas <?php echo $getSortIcon('recipients'); ?>"></i>
                                </a>
                            </th>
                            <th class="col-subject">
                                <a class="sort-link <?php echo $sort === 'subject' ? 'active' : ''; ?>" href="<?php echo $buildSortLink('subject'); ?>">
                                    <?php echo htmlspecialchars(__('msg_subject')); ?>
                                    <i class="fas <?php echo $getSortIcon('subject'); ?>"></i>
                                </a>
                            </th>
                            <th class="col-action">
                                <a class="sort-link <?php echo $sort === 'action' ? 'active' : ''; ?>" href="<?php echo $buildSortLink('action'); ?>">
                                    <?php echo htmlspecialchars(__('action')); ?>
                                    <i class="fas <?php echo $getSortIcon('action'); ?>"></i>
                                </a>
                            </th>
                            <th class="col-score">
                                <a class="sort-link <?php echo $sort === 'score' ? 'active' : ''; ?>" href="<?php echo $buildSortLink('score'); ?>">
                                    <?php echo htmlspecialchars(__('msg_score')); ?>
                                    <i class="fas <?php echo $getSortIcon('score'); ?>"></i>
                                </a>
                            </th>
                            <th style="width: 180px;">
                                <?php echo htmlspecialchars(__('status_explanation')); ?>
                            </th>
                            <th class="col-ip">
                                <a class="sort-link <?php echo $sort === 'ip_address' ? 'active' : ''; ?>" href="<?php echo $buildSortLink('ip_address'); ?>">
                                    <?php echo htmlspecialchars(__('ip_address')); ?>
                                    <i class="fas <?php echo $getSortIcon('ip_address'); ?>"></i>
                                </a>
                            </th>
                            <th class="col-hostname">
                                <a class="sort-link <?php echo $sort === 'hostname' ? 'active' : ''; ?>" href="<?php echo $buildSortLink('hostname'); ?>">
                                    <?php echo htmlspecialchars(__('hostname')); ?>
                                    <i class="fas <?php echo $getSortIcon('hostname'); ?>"></i>
                                </a>
                            </th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($messages as $msg): ?>
                            <?php
                            $msgId = $msg['id'];
                            $sender = decodeMimeHeader($msg['sender']);
                            $senderEmail = extractEmailAddress($sender);
                            $senderEmailKey = $senderEmail ? strtolower($senderEmail) : '';
                            $recipients = decodeMimeHeader($msg['recipients']);
                            $subject = decodeMimeHeader($msg['subject']) ?: __('msg_no_subject');
                            $score = round($msg['score'], 2);
                            $timestamp = date('d.m. H:i', strtotime($msg['timestamp']));
                            $action = $msg['action'] ?? 'unknown';
                            $ipAddress = $msg['ip_address'] ?? '-';
                            $hostname = $msg['hostname'] ?? '-';
                            $symbols = $msg['symbols'] ?? '';
                            $symbolData = buildMessageSymbolData($symbols);
                            $parsed_symbols = $symbolData['parsed_symbols'];
                            $hasVirusSymbol = $symbolData['has_virus_symbol'];
                            $hasBadAttachmentSymbol = $symbolData['has_bad_attachment_symbol'];
                            $statusSymbolMatches = $symbolData['status_symbol_matches'];
                            $virusClass = $hasVirusSymbol ? 'has-virus' : '';
                            $isRandomSender = $senderEmail ? isLikelyRandomEmail($senderEmail) : false;

                            // Action class - using existing badge CSS
                            $actionClass = 'badge-pass';
                            $actionIcon = 'fa-check-circle';

                            switch (strtolower($action)) {
                                case 'reject':
                                    $actionClass = 'badge badge-reject';
                                    $actionIcon = 'fa-ban';
                                    break;
                                case 'no action':
                                case 'pass':
                                    $actionClass = 'badge badge-pass';
                                    $actionIcon = 'fa-check-circle';
                                    break;
                                case 'add header':
                                    $actionClass = 'badge badge-header';
                                    $actionIcon = 'fa-tag';
                                    break;
                                case 'greylist':
                                    $actionClass = 'badrge badge-pass';
                                    $actionIcon = 'fa-clock';
                                    break;
                                case 'soft reject':
                                case 'soft_reject':
                                    $actionClass = 'badge badge-soft-reject';
                                    $actionIcon = 'fa-exclamation-triangle';
                                    break;
                                default:
                                    $actionClass = 'badge-pass';
                                    $actionIcon = 'fa-question-circle';
                            }

                            $scoreClass = getScoreBadgeClass($score, $action);
                            ?>
                            <tr class="<?php echo $virusClass; ?>">
                                <td class="timestamp"><?php echo htmlspecialchars($timestamp); ?></td>
                                <td class="email-field">
                                    <i class="fas fa-paper-plane"></i> 
                                    <a href="?sender=<?php echo urlencode($sender); ?>" 
                                       class="email-link" 
                                       title="<?php echo htmlspecialchars(__('filter_by_sender', ['sender' => $sender])); ?>">
                                        <?php echo htmlspecialchars(truncateText($sender, 40)); ?>
                                    </a>
                                <?php if ($canManageMaps && $senderEmail && !$isRandomSender): ?>
                                    <span class="sender-actions">
                                        <form method="POST" action="map_quick_add.php" class="sender-action-form">
                                            <input type="hidden" name="list_type" value="whitelist">
                                            <input type="hidden" name="entry_value" value="<?php echo htmlspecialchars($senderEmail); ?>">
                                            <input type="hidden" name="return_url" value="<?php echo htmlspecialchars($returnUrl); ?>">
                                            <button type="submit" class="sender-action-btn whitelist-btn<?php echo isset($listedEmails['whitelist'][$senderEmailKey]) ? ' is-listed' : ''; ?>" title="<?php echo htmlspecialchars(__('maps_add_whitelist_sender')); ?>">
                                                <i class="fas fa-shield-alt"></i>
                                            </button>
                                        </form>
                                        <form method="POST" action="map_quick_add.php" class="sender-action-form">
                                            <input type="hidden" name="list_type" value="blacklist">
                                            <input type="hidden" name="entry_value" value="<?php echo htmlspecialchars($senderEmail); ?>">
                                            <input type="hidden" name="return_url" value="<?php echo htmlspecialchars($returnUrl); ?>">
                                            <button type="submit" class="sender-action-btn blacklist-btn<?php echo isset($listedEmails['blacklist'][$senderEmailKey]) ? ' is-listed' : ''; ?>" title="<?php echo htmlspecialchars(__('maps_add_blacklist_sender')); ?>">
                                                <i class="fas fa-ban"></i>
                                            </button>
                                        </form>
                                    </span>
                                <?php endif; ?>
                                </td>
                                <td class="email-field">
                                    <i class="fas fa-inbox"></i> 
                                    <a href="?recipient=<?php echo urlencode($recipients); ?>" 
                                       class="email-link" 
                                       title="<?php echo htmlspecialchars(__('filter_by_recipient', ['recipient' => $recipients])); ?>">
                                        <?php echo htmlspecialchars(truncateText($recipients, 40)); ?>
                                    </a>
                                </td>
                                <td class="subject-field" title="<?php echo htmlspecialchars($subject); ?>">
                                    <span class="subject-text"><?php echo htmlspecialchars(truncateText($subject, 50)); ?></span>
                                    <?php if ($canManageMaps && !empty(trim($subject))): ?>
                                        <span class="sender-actions subject-actions">
                                            <button type="button" class="sender-action-btn whitelist-btn subject-map-btn" data-list-type="whitelist" data-subject="<?php echo htmlspecialchars($subject, ENT_QUOTES); ?>" title="<?php echo htmlspecialchars(__('maps_add_whitelist_subject')); ?>">
                                                <i class="fas fa-shield-alt"></i>
                                            </button>
                                            <button type="button" class="sender-action-btn blacklist-btn subject-map-btn" data-list-type="blacklist" data-subject="<?php echo htmlspecialchars($subject, ENT_QUOTES); ?>" title="<?php echo htmlspecialchars(__('maps_add_blacklist_subject')); ?>">
                                                <i class="fas fa-ban"></i>
                                            </button>
                                        </span>
                                    <?php endif; ?>
                                </td>
                                <td class="action-cell">
                                    <span class="action-badge <?php echo $actionClass; ?>">
                                        <i class="fas <?php echo $actionIcon; ?>"></i>
                                        <?php echo htmlspecialchars($action); ?>
                                    </span>
                                </td>
                                <td class="score-cell">
                                    <span class="score-badge <?php echo $scoreClass; ?>">
                                        <?php echo number_format($score, 2); ?>
                                        <?php if ($hasVirusSymbol): ?>
                                            <i class="fas fa-biohazard virus-icon" title="<?php echo htmlspecialchars(__('filter_virus')); ?>"></i>
                                        <?php endif; ?>
                                        <?php if ($hasBadAttachmentSymbol): ?>
                                            <i class="fas fa-paperclip bad-attachment-icon" title="<?php echo htmlspecialchars(__('filter_dangerous_attachment')); ?>"></i>
                                        <?php endif; ?>

                                        <!-- Symbols popup on hover -->
                                        <?php if (!empty($parsed_symbols)): ?>
                                            <div class="symbols-popup">
                                                <div class="symbols-popup-header">
                                                    <i class="fas fa-list-ul"></i> <?php echo htmlspecialchars(__('symbols_header', ['count' => count($parsed_symbols)])); ?>
                                                </div>
                                                <div class="symbols-grid">
                                                    <?php foreach ($parsed_symbols as $sym): 
                                                        $sym_score = $sym['score'];
                                                        $bg_color = getSymbolBadgeColor($sym_score);
                                                    ?>
                                                        <span class="symbol-badge" style="background: <?php echo $bg_color; ?>;">
                                                            <span class="symbol-name" title="<?php echo htmlspecialchars($sym['name']); ?>">
                                                                <?php echo htmlspecialchars($sym['name']); ?>
                                                            </span>
                                                            <span class="symbol-score">
                                                                <?php echo number_format($sym_score, 1); ?>
                                                            </span>
                                                        </span>
                                                    <?php endforeach; ?>
                                                </div>
                                            </div>
                                        <?php endif; ?>
                                    </span>
                                </td>
                                <td class="status-explanation-cell">
                                    <?php
                                    $hasStatusExplanation = false;
                                    foreach ($statusSymbolMatches as $groupSymbols) {
                                        if (!empty($groupSymbols)) {
                                            $hasStatusExplanation = true;
                                            break;
                                        }
                                    }
                                    ?>
                                    <?php if ($hasStatusExplanation): ?>
                                        <div class="status-pills">
                                            <?php foreach ($statusSymbolMatches as $groupKey => $groupSymbols): ?>
                                                <?php foreach ($groupSymbols as $groupSymbol): ?>
                                                    <span class="status-pill status-pill--<?php echo htmlspecialchars($groupKey); ?>">
                                                        <?php echo htmlspecialchars($groupSymbol); ?>
                                                    </span>
                                                <?php endforeach; ?>
                                            <?php endforeach; ?>
                                        </div>
                                    <?php else: ?>
                                        <span class="text-muted">-</span>
                                    <?php endif; ?>
                                </td>
                                <td class="ip-field">
                                    <a href="?ip=<?php echo urlencode($ipAddress); ?>" 
                                       class="ip-link" 
                                       title="<?php echo htmlspecialchars(__('filter_by_ip', ['ip' => $ipAddress])); ?>">
                                        <?php echo htmlspecialchars($ipAddress); ?>
                                    </a>
                                </td>
                                <td class="hostname-field">
                                    <?php echo htmlspecialchars($hostname); ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>

            <!-- Pagination -->
            <?php if ($totalPages > 1): ?>
                <div class="pagination">
                    <?php
                    $currentQuery = $filters;
                    $currentQuery['sort'] = $sort;
                    $currentQuery['dir'] = $sortDir;
                    $maxButtons = 7;
                    $startPage = max(1, $page - floor($maxButtons / 2));
                    $endPage = min($totalPages, $startPage + $maxButtons - 1);
                    $startPage = max(1, $endPage - $maxButtons + 1);
                    ?>

                    <?php if ($page > 1): ?>
                        <a href="?<?php echo buildQueryString(array_merge($currentQuery, ['page' => 1])); ?>" 
                           class="page-btn" title="<?php echo htmlspecialchars(__('pagination_first_page')); ?>">
                            <i class="fas fa-angle-double-left"></i>
                        </a>
                        <a href="?<?php echo buildQueryString(array_merge($currentQuery, ['page' => $page - 1])); ?>" 
                           class="page-btn" title="<?php echo htmlspecialchars(__('pagination_previous')); ?>">
                            <i class="fas fa-angle-left"></i>
                        </a>
                    <?php endif; ?>

                    <?php for ($i = $startPage; $i <= $endPage; $i++): ?>
                        <a href="?<?php echo buildQueryString(array_merge($currentQuery, ['page' => $i])); ?>" 
                           class="page-btn <?php echo $i === $page ? 'active' : ''; ?>">
                            <?php echo $i; ?>
                        </a>
                    <?php endfor; ?>

                    <?php if ($page < $totalPages): ?>
                        <a href="?<?php echo buildQueryString(array_merge($currentQuery, ['page' => $page + 1])); ?>" 
                           class="page-btn" title="<?php echo htmlspecialchars(__('pagination_next')); ?>">
                            <i class="fas fa-angle-right"></i>
                        </a>
                        <a href="?<?php echo buildQueryString(array_merge($currentQuery, ['page' => $totalPages])); ?>" 
                           class="page-btn" title="<?php echo htmlspecialchars(__('pagination_last_page')); ?>">
                            <i class="fas fa-angle-double-right"></i>
                        </a>
                    <?php endif; ?>
                </div>
            <?php endif; ?>
        <?php endif; ?>
    </div>

    <div id="subjectMapModal" class="modal" aria-hidden="true">
        <div class="modal-content">
            <div class="modal-header">
                <h3 id="subjectMapModalTitle"><i class="fas fa-tag"></i> <?php echo htmlspecialchars(__('maps_add_subject')); ?></h3>
                <button type="button" class="modal-close" aria-label="<?php echo htmlspecialchars(__('close')); ?>">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="modal-body">
                <form id="subjectMapForm" method="POST" action="map_quick_add.php">
                    <input type="hidden" name="list_type" id="subjectMapListType" value="">
                    <input type="hidden" name="entry_type" value="subject">
                    <input type="hidden" name="return_url" value="<?php echo htmlspecialchars($returnUrl); ?>">
                    <div class="form-group">
                        <label for="subjectMapValue"><?php echo htmlspecialchars(__('msg_subject')); ?></label>
                        <input type="text" id="subjectMapValue" name="entry_value" class="form-control" placeholder="<?php echo htmlspecialchars(__('maps_subject_placeholder')); ?>" required>
                        <small><?php echo htmlspecialchars(__('maps_subject_hint')); ?></small>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary modal-close"><?php echo htmlspecialchars(__('cancel')); ?></button>
                        <button type="submit" class="btn btn-primary"><?php echo htmlspecialchars(__('maps_add_entry')); ?></button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <script>
        const subjectModal = document.getElementById('subjectMapModal');
        const subjectModalTitle = document.getElementById('subjectMapModalTitle');
        const subjectModalValue = document.getElementById('subjectMapValue');
        const subjectModalListType = document.getElementById('subjectMapListType');
        const subjectStrings = {
            whitelist: "<?php echo htmlspecialchars(__('maps_add_whitelist_subject')); ?>",
            blacklist: "<?php echo htmlspecialchars(__('maps_add_blacklist_subject')); ?>"
        };

        function escapeRegex(value) {
            return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\//g, '\\/');
        }

        function openSubjectModal(listType, subject) {
            subjectModalListType.value = listType;
            subjectModalTitle.innerHTML = `<i class="fas fa-tag"></i> ${subjectStrings[listType]}`;
            const trimmedSubject = subject.trim();
            subjectModalValue.value = trimmedSubject ? `/${escapeRegex(trimmedSubject)}/` : '';
            subjectModal.classList.add('active');
            subjectModal.setAttribute('aria-hidden', 'false');
            subjectModalValue.focus();
        }

        function closeSubjectModal() {
            subjectModal.classList.remove('active');
            subjectModal.setAttribute('aria-hidden', 'true');
        }

        document.querySelectorAll('.subject-map-btn').forEach((button) => {
            button.addEventListener('click', () => {
                openSubjectModal(button.dataset.listType, button.dataset.subject || '');
            });
        });

        subjectModal.querySelectorAll('.modal-close').forEach((button) => {
            button.addEventListener('click', closeSubjectModal);
        });

        subjectModal.addEventListener('click', (event) => {
            if (event.target === subjectModal) {
                closeSubjectModal();
            }
        });

        function toggleFilters() {
            const content = document.getElementById('filterContent');
            const icon = document.querySelector('.toggle-icon');
            content.classList.toggle('active');
            icon.classList.toggle('rotated');
        }
    </script>
</body>
</html>
