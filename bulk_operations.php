<?php
/*
 * Version: 2.0.0
 * Author: Martin Pouzar
 * License: GNU General Public License v3.0
 */
/**
 * Bulk Operations - Mass operations on quarantined messages
 * Updated: Radio buttons, compact table, auto-learn, state colors
 */

session_start();
require_once 'config.php';
require_once 'filter_helper.php';
require_once 'lang_helper.php';

// Authentication check
if (!isAuthenticated()) {
    header('Location: login.php');
    exit;
}

// Permission check
$userRole = $_SESSION['user_role'] ?? 'viewer';
if (!checkPermission('domain_admin')) {
    die(__('bulk_permission_denied'));
}

$db = Database::getInstance()->getConnection();
$user = $_SESSION['username'] ?? 'unknown';
$returnUrl = $_SERVER['REQUEST_URI'] ?? 'bulk_operations.php';
$canManageMaps = checkPermission('domain_admin');

// Get filters from request
$pageSessionKey = 'bulk_operations_page';
if (isset($_GET['reset_page']) && $_GET['reset_page'] == '1') {
    unset($_SESSION[$pageSessionKey]);
}
if (isset($_GET['reset_filters']) && $_GET['reset_filters'] == '1') {
    unset($_SESSION[$pageSessionKey]);
}
$filters = getFiltersFromRequest();

// Sorting
$sortableColumns = [
    'timestamp' => 'timestamp',
    'sender' => 'sender',
    'recipients' => 'recipients',
    'subject' => 'subject',
    'country' => 'country',    
    'size' => 'size',    
    'score' => 'score',
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
$page = $_SESSION[$pageSessionKey] ?? 1;
if (isset($_GET['reset_page']) && $_GET['reset_page'] == '1') {
    $page = 1;
}
if (isset($_GET['page'])) {
    $page = max(1, (int)$_GET['page']);
    $_SESSION[$pageSessionKey] = $page;
}
$offset = ($page - 1) * ITEMS_PER_PAGE;

// Get total count
$totalItems = countQuarantineMessages($db, $filters);
$totalPages = max(1, (int)ceil($totalItems / ITEMS_PER_PAGE));

// Build and execute query
$params = [];
$sql = buildQuarantineQuery($filters, $params, [
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

// Fetch symbols for messages if not included in query
foreach ($messages as &$msg) {
    if (!isset($msg['symbols']) || empty($msg['symbols'])) {
        $symbolStmt = $db->prepare("SELECT symbols FROM quarantine_messages WHERE id = ?");
        $symbolStmt->execute([$msg['id']]);
        $symbolData = $symbolStmt->fetch(PDO::FETCH_ASSOC);
        $msg['symbols'] = $symbolData['symbols'] ?? '';
    }
}
unset($msg); // Break reference


// Get statistics
$stats = getExtendedQuarantineStats($db, $filters);

$page_title = __('bulk_page_title', ['app' => __('app_title')]);
include 'menu.php';
?>

<!DOCTYPE html>
<html lang="<?php echo htmlspecialchars(currentLang()); ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($page_title); ?></title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/flag-icons/6.6.6/css/flag-icons.min.css">
    <link rel="stylesheet" href="css/style.css">
    <link rel="stylesheet" href="css/stats-inline.css">
    <link rel="stylesheet" href="css/bulk.css">
</head>
<body>
    <div class="container">
        <!-- HEADER WITH STATISTICS -->
        <div class="header-with-stats">
            <div class="header-title">
                <h1><i class="fas fa-tasks"></i> <?php echo htmlspecialchars(__('bulk_title')); ?></h1>
            </div>
            <div>
                <?php
                echo renderStatsInline($stats, [
                    'show_total' => true,
                    'show_rejected' => true,
                    'show_quarantined' => true,
                    'show_learned_ham' => true,
                    'show_learned_spam' => true,
                    'show_released' => true,
                    'show_avg_score' => true,
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
            'show_state' => true,
            'show_ip' => false,
            'show_country' => true,
            'show_auth_user' => false,
            'form_id' => 'filterForm',
            'reset_url' => 'bulk_operations.php?reset_filters=1',
        ]));
        ?>

        <!-- Action Legend -->
        <div class="action-legend">
            <div class="legend-item">
                <strong><?php echo htmlspecialchars(__('bulk_action_legend')); ?></strong>
            </div>
            <div class="legend-item">
                <span class="action-spam">⬤ S</span> = <?php echo htmlspecialchars(__('bulk_action_spam')); ?>
            </div>
            <div class="legend-item">
                <span class="action-ham">⬤ H</span> = <?php echo htmlspecialchars(__('bulk_action_ham')); ?>
            </div>
            <div class="legend-item">
                <span class="action-forget">⬤ F</span> = <?php echo htmlspecialchars(__('bulk_action_forget')); ?>
            </div>
            <div class="legend-item">
                <span class="action-release">☑ R</span> = <?php echo htmlspecialchars(__('bulk_action_release')); ?>
            </div>
        </div>

        <!-- Bulk Operations Info -->
        <div class="bulk-actions-info">
            <i class="fas fa-info-circle"></i>
            <strong><?php echo htmlspecialchars(__('bulk_instructions_label')); ?></strong> <?php echo htmlspecialchars(__('bulk_instructions_text')); ?>
        </div>

        <?php if (empty($messages)): ?>
            <div class="empty-state">
                <i class="fas fa-inbox"></i>
                <h3><?php echo htmlspecialchars(__('bulk_no_messages_title')); ?></h3>
                <p><?php echo htmlspecialchars(__('bulk_no_messages_desc')); ?></p>
            </div>
        <?php else: ?>
            <form method="POST" action="process_bulk.php" id="bulkForm">
                <div class="results-info">
                    <?php echo __(
                        'bulk_results_info',
                        [
                            'shown' => count($messages),
                            'total' => number_format($totalItems),
                            'page' => $page,
                            'pages' => $totalPages,
                        ]
                    ); ?>
                </div>

                <table class="messages-table">
                    <?php
                    echo renderMessagesTableHeader([
                        'sort' => $sort,
                        'buildSortLink' => $buildSortLink,
                        'getSortIcon' => $getSortIcon,
                        'columns' => [
                            ['key' => 'timestamp', 'style' => 'width: 110px;'],
                            'sender',
                            'recipients',
                            'subject',
                            ['key' => 'country', 'style' => 'width: 50px;', 'sortable' => true],
                            ['key' => 'size', 'style' => 'width: 90px;', 'sortable' => true],
                            ['key' => 'score', 'style' => 'width: 60px;'],
                            ['key' => 'status', 'style' => 'col-status'],
                            ['key' => 'actions', 'style' => 'width: 180px;'],
                        ],
                    ]);
                    ?>
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
                            $action = strtolower(trim($msg['action'] ?? ''));
                            $ipAddress = $msg['ip_address'] ?? '';
                            $countryCode = strtolower(trim((string)($msg['country'] ?? getCountryCodeForIp($ipAddress))));
                            $countryTitle = $countryCode !== '' ? strtoupper($countryCode) : '-';
                            $countryLink = $countryCode !== ''
                                ? '?' . buildQueryString(array_merge($filters, ['country' => $countryCode, 'page' => 1]))
                                : '';
                            $flag = $countryCode !== ''
                                ? '<span class="fi fi-' . htmlspecialchars($countryCode) . '" title="' . htmlspecialchars($countryTitle) . '"></span>'
                                : '-';

                            $symbols = $msg['symbols'] ?? '';
                            $symbolData = buildMessageSymbolData($symbols);
                            $parsedSymbols = $symbolData['parsed_symbols'];
                            $hasVirusSymbol = $symbolData['has_virus_symbol'];
                            $hasBadAttachmentSymbol = $symbolData['has_bad_attachment_symbol'];
                            $statusSymbolMatches = $symbolData['status_symbol_matches'];
                            $timestamp = date('d.m. H:i', strtotime($msg['timestamp']));

                            $scoreClass = getScoreBadgeClass($score, $action);

                            // Unique name for radio group
                            $radioName = 'action_' . $msgId;

                            // State class for row coloring
                            $stateClass = getMessageStateClass((int)$msg['state']);
                            $statusRowClass = getStatusRowClass($statusSymbolMatches);

                            // Auto-learn spam detection by Rspamd
                            // Check if Rspamd already auto-learned this message
                            $autoLearnEnabled = defined('AUTOLEARN_ENABLED') ? AUTOLEARN_ENABLED : false;
                            $autoLearnScore = defined('AUTOLEARN_SCORE') ? AUTOLEARN_SCORE : 15.0;
                            $isAutoLearnSpam = false;

                            if ($autoLearnEnabled) {
                                $hasAutoLearn = ($msg['state'] == 0 && $score >= $autoLearnScore);

                                if ($hasAutoLearn) {
                                    $stateClass = 'auto-learn-spam';
                                    $isAutoLearnSpam = true;
                                }
                            }
                            $virusClass = $hasVirusSymbol ? 'has-virus' : '';
                            $isRandomSender = $senderEmail ? isLikelyRandomEmail($senderEmail) : false;
                            ?>
                            <tr class="message-row <?php echo trim($stateClass . ' ' . $virusClass . ' ' . $statusRowClass); ?>" id="row_<?php echo $msgId; ?>">
                                <td class="timestamp"><?php echo htmlspecialchars($timestamp); ?></td>
                                <td class="email-field">
                                    <i class="fas fa-paper-plane"></i> 
                                    <a href="?sender=<?php echo urlencode($sender); ?>" 
                                       class="email-link" 
                                       title="<?php echo htmlspecialchars(__('filter_by_sender', ['sender' => $sender])); ?>">
                                        <?php echo htmlspecialchars(truncateText($sender, 40)); ?>
                                    </a>
                                <?php if ($canManageMaps && $senderEmail && !$isRandomSender): ?>
                                    <?php
                                    $isWhitelisted = isset($listedEmails['whitelist'][$senderEmailKey]);
                                    $isBlacklisted = isset($listedEmails['blacklist'][$senderEmailKey]);
                                    ?>
                                    <span class="sender-actions">
                                        <?php if ($isWhitelisted): ?>
                                            <form method="POST" action="map_quick_add.php" class="sender-action-form" onsubmit="return confirm('<?php echo htmlspecialchars(__('maps_confirm_delete')); ?>');">
                                                <input type="hidden" name="action" value="delete">
                                                <input type="hidden" name="list_type" value="whitelist">
                                                <input type="hidden" name="entry_type" value="email">
                                                <input type="hidden" name="entry_value" value="<?php echo htmlspecialchars($senderEmail); ?>">
                                                <input type="hidden" name="return_url" value="<?php echo htmlspecialchars($returnUrl); ?>">
                                                <button type="submit" class="sender-action-btn whitelist-btn is-listed" title="<?php echo htmlspecialchars(__('maps_remove_whitelist_sender')); ?>">
                                                    <i class="fas fa-xmark"></i>
                                                </button>
                                            </form>
                                        <?php else: ?>
                                            <button type="button" class="sender-action-btn whitelist-btn sender-map-btn" data-list-type="whitelist" data-sender="<?php echo htmlspecialchars($senderEmail, ENT_QUOTES); ?>" title="<?php echo htmlspecialchars(__('maps_add_whitelist_sender')); ?>">
                                                <i class="fas fa-shield-alt"></i>
                                            </button>
                                        <?php endif; ?>
                                        <?php if ($isBlacklisted): ?>
                                            <form method="POST" action="map_quick_add.php" class="sender-action-form" onsubmit="return confirm('<?php echo htmlspecialchars(__('maps_confirm_delete')); ?>');">
                                                <input type="hidden" name="action" value="delete">
                                                <input type="hidden" name="list_type" value="blacklist">
                                                <input type="hidden" name="entry_type" value="email">
                                                <input type="hidden" name="entry_value" value="<?php echo htmlspecialchars($senderEmail); ?>">
                                                <input type="hidden" name="return_url" value="<?php echo htmlspecialchars($returnUrl); ?>">
                                                <button type="submit" class="sender-action-btn blacklist-btn is-listed" title="<?php echo htmlspecialchars(__('maps_remove_blacklist_sender')); ?>">
                                                    <i class="fas fa-xmark"></i>
                                                </button>
                                            </form>
                                        <?php else: ?>
                                            <button type="button" class="sender-action-btn blacklist-btn sender-map-btn" data-list-type="blacklist" data-sender="<?php echo htmlspecialchars($senderEmail, ENT_QUOTES); ?>" title="<?php echo htmlspecialchars(__('maps_add_blacklist_sender')); ?>">
                                                <i class="fas fa-ban"></i>
                                            </button>
                                        <?php endif; ?>
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
                                <td class="subject-field">
                                    <button type="button" class="subject-preview-btn" data-message-id="<?php echo $msgId; ?>" aria-label="<?php echo htmlspecialchars(__('preview_message_title')); ?>">
                                        <?php echo htmlspecialchars(truncateText($subject, 60)); ?>
                                    </button>
                                </td>
                                <td class="text-center">
                                    <?php if ($countryLink !== ''): ?>
                                        <a href="<?php echo htmlspecialchars($countryLink); ?>" class="country-link" title="<?php echo htmlspecialchars(__('filter_by_country', ['country' => $countryTitle])); ?>">
                                            <?php echo $flag; ?>
                                        </a>
                                    <?php else: ?>
                                        <?php echo $flag; ?>
                                    <?php endif; ?>
                                </td>
                                <td class="text-right no-wrap">
                                    <?php echo htmlspecialchars(formatMessageSize((int)($msg['size_bytes'] ?? 0))); ?>
                                </td>
                                <td class="text-center score-cell">
                                    <span class="score-badge <?php echo $scoreClass; ?>">
                                        <?php echo $score; ?>
                                        <?php if ($hasVirusSymbol): ?>
                                            <i class="fas fa-biohazard virus-icon" title="<?php echo htmlspecialchars(__('filter_virus')); ?>"></i>
                                        <?php endif; ?>
                                        <?php if ($hasBadAttachmentSymbol): ?>
                                            <i class="fas fa-paperclip bad-attachment-icon" title="<?php echo htmlspecialchars(__('filter_dangerous_attachment')); ?>"></i>
                                        <?php endif; ?>

                                        <?php if (!empty($parsedSymbols)): ?>
                                        <div class="symbols-popup">
                                            <div class="symbols-popup-header">
                                                <i class="fas fa-list-ul"></i> <?php echo htmlspecialchars(__('symbols_header', ['count' => count($parsedSymbols)])); ?>
                                            </div>
                                            <div class="symbols-grid">
                                                <?php foreach ($parsedSymbols as $sym): 
                                                    $symScore = $sym['score'];
                                                    $bgcolor = getSymbolBadgeColor($symScore);
                                                ?>
                                                <span class="symbol-badge" style="background: <?php echo $bgcolor; ?>">
                                                    <span class="symbol-name" title="<?php echo htmlspecialchars($sym['name']); ?>">
                                                        <?php echo htmlspecialchars($sym['name']); ?>
                                                    </span>
                                                    <span class="symbol-score">
                                                        <?php echo number_format($symScore, 2); ?>
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
                                <td class="text-center">
                                    <div class="action-controls">
                                        <label class="action-label action-spam" title="<?php echo htmlspecialchars(__('bulk_action_spam')); ?>">
                                            <input type="radio" name="<?php echo $radioName; ?>" value="spam" class="action-radio" onchange="updateRowState('<?php echo $msgId; ?>')" <?php echo $isAutoLearnSpam ? 'checked' : ''; ?>>
                                            <span>S</span><?php if ($isAutoLearnSpam) echo ' <i class="fas fa-robot" style="font-size:9px;" title="' . htmlspecialchars(__('bulk_auto_learned')) . '"></i>'; ?>
                                        </label>
                                        <label class="action-label action-ham" title="<?php echo htmlspecialchars(__('bulk_action_ham')); ?>">
                                            <input type="radio" name="<?php echo $radioName; ?>" value="ham" class="action-radio" onchange="updateRowState('<?php echo $msgId; ?>')">
                                            <span>H</span>
                                        </label>
                                        <label class="action-label action-forget" title="<?php echo htmlspecialchars(__('bulk_action_forget')); ?>">
                                            <input type="radio" name="<?php echo $radioName; ?>" value="forget" class="action-radio" onchange="updateRowState('<?php echo $msgId; ?>')">
                                            <span>F</span>
                                        </label>
                                        <label class="action-label action-release" title="<?php echo htmlspecialchars(__('bulk_action_release_short')); ?>">
                                            <input type="checkbox" name="release_<?php echo $msgId; ?>" value="1" class="action-checkbox" onchange="updateRowState('<?php echo $msgId; ?>')">
                                            <span>R</span>
                                        </label>
                                    </div>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>

                <!-- Bulk Submit Button -->
                <div class="bulk-submit-container">
                    <button type="submit" class="bulk-submit-btn" id="bulkSubmitBtn" disabled>
                        <i class="fas fa-play-circle"></i> <?php echo htmlspecialchars(__('bulk_submit')); ?>
                        <span class="selected-count" id="selectedCount">0</span>
                    </button>
                    <div style="margin-top: 10px; color: #6c757d; font-size: 13px;">
                        <i class="fas fa-info-circle"></i> <?php echo htmlspecialchars(__('bulk_submit_hint')); ?>
                    </div>
                </div>

                <!-- Pagination -->
                <?php
                $paginationQuery = array_diff_key($_GET, ['page' => '', 'reset_page' => '']);
                echo renderPagination($page, $totalPages, $paginationQuery, [
                    'max_buttons' => 5,
                    'link_class' => 'page-link',
                    'prev_label' => '<i class="fas fa-chevron-left"></i> ' . htmlspecialchars(__('pagination_previous')),
                    'next_label' => htmlspecialchars(__('pagination_next')) . ' <i class="fas fa-chevron-right"></i>',
                ]);
                ?>
            </form>
        <?php endif; ?>
    </div>

    <?php
    echo renderMapModal([
        'id' => 'senderMapModal',
        'title_id' => 'senderMapModalTitle',
        'title_text' => __('maps_add_sender'),
        'icon_class' => 'fas fa-paper-plane',
        'form_id' => 'senderMapForm',
        'list_type_id' => 'senderMapListType',
        'entry_type' => 'email',
        'return_url' => $returnUrl,
        'label_text' => __('msg_sender'),
        'value_id' => 'senderMapValue',
        'placeholder_text' => __('maps_sender_placeholder'),
        'hint_text' => __('maps_sender_hint'),
        'include_action' => true,
        'action_value' => 'add'
    ]);
    ?>

    <script>
    const bulkStrings = {
        selectActionAlert: <?php echo json_encode(__('bulk_select_action_alert')); ?>,
        confirmOperations: <?php echo json_encode(__('bulk_confirm_operations')); ?>,
        previewLoading: <?php echo json_encode(__('preview_loading')); ?>,
        previewErrorLabel: <?php echo json_encode(__('error')); ?>,
        previewParseError: <?php echo json_encode(__('preview_parse_error')); ?>,
        previewLoadFailed: <?php echo json_encode(__('preview_load_failed')); ?>,
        previewNetworkError: <?php echo json_encode(__('preview_network_error')); ?>,
        previewTitle: <?php echo json_encode(__('preview_message_title')); ?>,
        previewSender: <?php echo json_encode(__('msg_sender')); ?>,
        previewSubject: <?php echo json_encode(__('msg_subject')); ?>,
        previewTime: <?php echo json_encode(__('time')); ?>,
        previewScore: <?php echo json_encode(__('msg_score')); ?>,
        previewModeHtml: <?php echo json_encode(__('preview_mode_html')); ?>,
        previewModeText: <?php echo json_encode(__('preview_mode_text')); ?>
    };

    const senderModal = document.getElementById('senderMapModal');
    const senderModalTitle = document.getElementById('senderMapModalTitle');
    const senderModalValue = document.getElementById('senderMapValue');
    const senderModalListType = document.getElementById('senderMapListType');
    const senderStrings = {
        whitelist: <?php echo json_encode(__('maps_add_whitelist_sender')); ?>,
        blacklist: <?php echo json_encode(__('maps_add_blacklist_sender')); ?>
    };

    function openSenderModal(listType, sender) {
        senderModalListType.value = listType;
        senderModalTitle.innerHTML = `<i class="fas fa-paper-plane"></i> ${senderStrings[listType]}`;
        senderModalValue.value = sender.trim();
        senderModal.classList.add('active');
        senderModal.setAttribute('aria-hidden', 'false');
        senderModalValue.focus();
    }

    function closeSenderModal() {
        senderModal.classList.remove('active');
        senderModal.setAttribute('aria-hidden', 'true');
    }

    document.querySelectorAll('.sender-map-btn').forEach((button) => {
        button.addEventListener('click', () => {
            openSenderModal(button.dataset.listType, button.dataset.sender || '');
        });
    });

    senderModal.querySelectorAll('.modal-close, .modal-dismiss').forEach((button) => {
        button.addEventListener('click', closeSenderModal);
    });

    senderModal.addEventListener('click', (event) => {
        if (event.target === senderModal) {
            closeSenderModal();
        }
    });

    // Update row visual state and count selected actions
    function updateRowState(msgId) {
        const row = document.getElementById('row_' + msgId);
        const radios = document.querySelectorAll('input[name="action_' + msgId + '"]');
        const checkbox = document.querySelector('input[name="release_' + msgId + '"]');

        // Check if any action is selected
        let hasAction = false;
        radios.forEach(function(radio) {
            if (radio.checked) hasAction = true;
        });
        if (checkbox && checkbox.checked) hasAction = true;

        // Update row visual state
        if (hasAction) {
            row.classList.add('has-action');
        } else {
            row.classList.remove('has-action');
        }

        updateSelectedCount();
    }

    // Count messages with selected actions
    function updateSelectedCount() {
        const allRadios = document.querySelectorAll('input[type="radio"]');
        const allCheckboxes = document.querySelectorAll('input[type="checkbox"][name^="release_"]');
        let count = 0;
        const processedMessages = new Set();

        // Count radio selections
        allRadios.forEach(function(radio) {
            if (radio.checked) {
                const msgId = radio.name.replace('action_', '');
                processedMessages.add(msgId);
            }
        });

        // Count checkbox selections
        allCheckboxes.forEach(function(checkbox) {
            if (checkbox.checked) {
                const msgId = checkbox.name.replace('release_', '');
                processedMessages.add(msgId);
            }
        });

        count = processedMessages.size;

        const countDisplay = document.getElementById('selectedCount');
        const submitBtn = document.getElementById('bulkSubmitBtn');

        if (countDisplay) {
            countDisplay.textContent = count;
        }

        if (submitBtn) {
            submitBtn.disabled = (count === 0);
        }
    }

    // Form validation before submit
    document.getElementById('bulkForm')?.addEventListener('submit', function(e) {
        const allRadios = document.querySelectorAll('input[type="radio"]:checked');
        const allCheckboxes = document.querySelectorAll('input[type="checkbox"][name^="release_"]:checked');

        if (allRadios.length === 0 && allCheckboxes.length === 0) {
            e.preventDefault();
            alert(bulkStrings.selectActionAlert);
            return false;
        }

        // Count total operations
        const processedMessages = new Set();
        allRadios.forEach(function(radio) {
            const msgId = radio.name.replace('action_', '');
            processedMessages.add(msgId);
        });
        allCheckboxes.forEach(function(checkbox) {
            const msgId = checkbox.name.replace('release_', '');
            processedMessages.add(msgId);
        });

        const count = processedMessages.size;

        // Confirmation
        if (!confirm(bulkStrings.confirmOperations.replace('{count}', count))) {
            e.preventDefault();
            return false;
        }
    });

    // Initialize on page load
    document.addEventListener('DOMContentLoaded', function() {
        // Update all rows including auto-learned ones
        const allRows = document.querySelectorAll('.message-row');
        allRows.forEach(function(row) {
            const msgId = row.id.replace('row_', '');
            updateRowState(msgId);
        });
        updateSelectedCount();
    });
    </script>

    <!-- Preview Tooltip -->
    <?php
    echo renderPreviewModal([
        'id' => 'messagePreviewModal',
        'classes' => 'preview-modal',
        'title_text' => __('preview_message_title'),
        'icon_class' => 'fas fa-envelope',
        'content_id' => 'previewModalContent',
        'content_class' => 'preview-modal-content',
        'loading_class' => 'preview-loading',
        'loading_text' => __('preview_loading')
    ]);
    ?>

    <script>
    let activeRequest = null;
    const previewModal = document.getElementById('messagePreviewModal');
    const previewModalContent = document.getElementById('previewModalContent');

    document.addEventListener('DOMContentLoaded', function() {
        document.querySelectorAll('.subject-preview-btn').forEach((button) => {
            button.addEventListener('click', () => {
                openPreviewModal(button.dataset.messageId);
            });
        });

        previewModal.querySelectorAll('.modal-close').forEach((button) => {
            button.addEventListener('click', closePreviewModal);
        });

        previewModal.addEventListener('click', (event) => {
            if (event.target === previewModal) {
                closePreviewModal();
            }
        });

        document.addEventListener('keydown', (event) => {
            if (event.key === 'Escape' && previewModal.classList.contains('active')) {
                closePreviewModal();
            }
        });
    });

    function openPreviewModal(msgId) {
        if (!msgId) {
            return;
        }

        if (activeRequest) {
            activeRequest.abort();
        }

        previewModalContent.innerHTML = '<div class="preview-loading"><i class="fas fa-spinner fa-spin"></i> ' + bulkStrings.previewLoading + '</div>';
        previewModal.classList.add('active');
        previewModal.setAttribute('aria-hidden', 'false');

        activeRequest = new XMLHttpRequest();
        activeRequest.open('GET', 'api_message_preview.php?id=' + encodeURIComponent(msgId) + '&format=auto', true);

        activeRequest.onload = function() {
            if (activeRequest.status === 200) {
                try {
                    const data = JSON.parse(activeRequest.responseText);

                    if (data.success) {
                        renderPreview(data);
                    } else {
                        previewModalContent.innerHTML = '<div class="preview-error">' + bulkStrings.previewErrorLabel + ': ' + escapeHtml(data.error) + '</div>';
                    }
                } catch (e) {
                    previewModalContent.innerHTML = '<div class="preview-error">' + bulkStrings.previewParseError + '</div>';
                }
            } else {
                previewModalContent.innerHTML = '<div class="preview-error">' + bulkStrings.previewLoadFailed + '</div>';
            }
            activeRequest = null;
        };

        activeRequest.onerror = function() {
            previewModalContent.innerHTML = '<div class="preview-error">' + bulkStrings.previewNetworkError + '</div>';
            activeRequest = null;
        };

        activeRequest.send();
    }

    function renderPreview(data) {
        let formatIndicator = '';
        if (data.is_html) {
            formatIndicator = `<span class="preview-format-indicator">
                <i class="fas fa-code"></i> ${bulkStrings.previewModeHtml}
            </span>`;
        } else if (data.has_html) {
            formatIndicator = `<span class="preview-format-indicator muted">
                <i class="fas fa-align-left"></i> ${bulkStrings.previewModeText}
            </span>`;
        }

        const metaHtml = `
            <div class="preview-meta"><strong>${bulkStrings.previewSender}:</strong> ${escapeHtml(data.sender)}</div>
            <div class="preview-meta"><strong>${bulkStrings.previewSubject}:</strong> ${escapeHtml(data.subject)}</div>
            <div class="preview-meta"><strong>${bulkStrings.previewTime}:</strong> ${escapeHtml(data.timestamp)} | <strong>${bulkStrings.previewScore}:</strong> ${data.score}</div>
        `;

        if (data.is_html) {
            previewModalContent.innerHTML = `
                <div class="preview-header">
                    <h4><i class="fas fa-envelope"></i> ${bulkStrings.previewTitle} ${formatIndicator}</h4>
                    ${metaHtml}
                </div>
                <div class="preview-message-body">
                    <iframe class="preview-iframe" sandbox="" referrerpolicy="no-referrer"></iframe>
                </div>
            `;
            const iframe = previewModalContent.querySelector('.preview-iframe');
            iframe.srcdoc = data.preview;
        } else {
            previewModalContent.innerHTML = `
                <div class="preview-header">
                    <h4><i class="fas fa-envelope"></i> ${bulkStrings.previewTitle} ${formatIndicator}</h4>
                    ${metaHtml}
                </div>
                <div class="preview-message-body">
                    <pre>${escapeHtml(data.preview)}</pre>
                </div>
            `;
        }
    }

    function closePreviewModal() {
        previewModal.classList.remove('active');
        previewModal.setAttribute('aria-hidden', 'true');

        if (activeRequest) {
            activeRequest.abort();
            activeRequest = null;
        }
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    </script>
    <?php include 'footer.php'; ?>
</body>
</html>
