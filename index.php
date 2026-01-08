<?php
/*
 * Version: 2.0.0
 * Author: Martin Pouzar
 * License: GNU General Public License v3.0
 */
/**
 * Rspamd Quarantine - Main Index
 * Updated: Compact table, state colors, preview tooltip, icon-only buttons, clickable emails
 */

session_start(); 
require_once 'config.php';
require_once 'lang_helper.php';
require_once 'filter_helper.php';

// Authentication check
if (!isAuthenticated()) {
    header('Location: login.php');
    exit;
}

$db = Database::getInstance()->getConnection();
$userRole = $_SESSION['user_role'] ?? 'viewer';
$user = $_SESSION['username'] ?? 'unknown';
$returnUrl = $_SERVER['REQUEST_URI'] ?? 'index.php';
$canManageMaps = checkPermission('domain_admin');

// Get filters from request
$pageSessionKey = 'index_page';
$resetPage = isset($_GET['reset_page']) && $_GET['reset_page'] == '1';
if (isset($_GET['reset_filters']) && $_GET['reset_filters'] == '1') {
    unset($_SESSION[$pageSessionKey]);
}
if ($resetPage) {
    unset($_SESSION[$pageSessionKey]);
}
$filters = getFiltersFromRequest();

// Sorting
$sortableColumns = [
    'timestamp' => 'timestamp',
    'sender' => 'sender',
    'recipients' => 'recipients',
    'subject' => 'subject',
    'score' => 'score',
    'hostname' => 'hostname',
    'size' => 'size',
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
if ($resetPage) {
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

$page_title = __('quarantine_title');
include 'menu.php';
?>

<!DOCTYPE html>
<html lang="<?php echo htmlspecialchars(currentLang()); ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($page_title); ?></title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link rel="stylesheet" href="css/style.css">
    <link rel="stylesheet" href="css/stats-inline.css">
    <link rel="stylesheet" href="css/index.css">
</head>
<body>
    <div class="container">
        <!-- Header with statistics -->
        <div class="header-with-stats">
            <div class="header-title">
                <h1><i class="fas fa-inbox"></i> <?php echo htmlspecialchars(__('quarantine_messages')); ?></h1>
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

        <!-- Filters -->
        <?php
        echo renderSearchFilters(getQuarantineFilters([
            'columns' => null,
            'show_search' => true,
            'show_action' => false,
            'show_score_min' => false,
            'show_score_max' => false,
            'show_dates' => true,
            'show_sender' => true,
            'show_recipient' => true,
            'show_state' => true,
            'show_ip' => false,
            'show_auth_user' => false,
            'show_virus' => true,
            'show_bad_extension' => true,
            'form_id' => 'filterForm',
            'reset_url' => 'index.php?reset_filters=1',
        ]));
        ?>

        <?php if (empty($messages)): ?>
            <div class="empty-state">
                <i class="fas fa-inbox"></i>
                <h3><?php echo htmlspecialchars(__('quarantine_no_messages')); ?></h3>
                <p><?php echo htmlspecialchars(__('quarantine_no_messages_desc')); ?></p>
            </div>
        <?php else: ?>
            <div class="results-info" style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <?php echo __(
                        'quarantine_results_info',
                        [
                            'shown' => count($messages),
                            'total' => number_format($totalItems),
                            'page' => $page,
                            'pages' => $totalPages,
                        ]
                    ); ?>
                </div>
                <label class="preview-toggle">
                    <input type="checkbox" id="htmlPreviewToggle" onchange="toggleHtmlPreview(this.checked)" style="width: 14px; height: 14px; cursor: pointer;">
                    <i class="fas fa-code"></i> <strong><?php echo htmlspecialchars(__('preview_html_toggle')); ?></strong>
                </label>
            </div>

            <table class="messages-table">
                <thead>
                    <tr>
                        <th style="width: 110px;">
                            <a class="sort-link <?php echo $sort === 'timestamp' ? 'active' : ''; ?>" href="<?php echo $buildSortLink('timestamp'); ?>">
                                <?php echo htmlspecialchars(__('time')); ?>
                                <i class="fas <?php echo $getSortIcon('timestamp'); ?>"></i>
                            </a>
                        </th>
                        <th>
                            <a class="sort-link <?php echo $sort === 'sender' ? 'active' : ''; ?>" href="<?php echo $buildSortLink('sender'); ?>">
                                <?php echo htmlspecialchars(__('msg_sender')); ?>
                                <i class="fas <?php echo $getSortIcon('sender'); ?>"></i>
                            </a>
                        </th>
                        <th>
                            <a class="sort-link <?php echo $sort === 'recipients' ? 'active' : ''; ?>" href="<?php echo $buildSortLink('recipients'); ?>">
                                <?php echo htmlspecialchars(__('msg_recipient')); ?>
                                <i class="fas <?php echo $getSortIcon('recipients'); ?>"></i>
                            </a>
                        </th>
                        <th>
                            <a class="sort-link <?php echo $sort === 'subject' ? 'active' : ''; ?>" href="<?php echo $buildSortLink('subject'); ?>">
                                <?php echo htmlspecialchars(__('subject')); ?>
                                <i class="fas <?php echo $getSortIcon('subject'); ?>"></i>
                            </a>
                        </th>            
                        <th style="width: 100px;" class="col-hostname">
                            <a class="sort-link <?php echo $sort === 'hostname' ? 'active' : ''; ?>" href="<?php echo $buildSortLink('hostname'); ?>">
                                <?php echo htmlspecialchars(__('hostname')); ?>
                                <i class="fas <?php echo $getSortIcon('hostname'); ?>"></i>
                            </a>
                        </th>
                        <th style="width: 90px;" class="col-size">
                            <a class="sort-link <?php echo $sort === 'size' ? 'active' : ''; ?>" href="<?php echo $buildSortLink('size'); ?>">
                                <?php echo htmlspecialchars(__('size')); ?>
                                <i class="fas <?php echo $getSortIcon('size'); ?>"></i>
                            </a>
                        </th>
                        <th style="width: 60px;">
                            <a class="sort-link <?php echo $sort === 'score' ? 'active' : ''; ?>" href="<?php echo $buildSortLink('score'); ?>">
                                <?php echo htmlspecialchars(__('msg_score')); ?>
                                <i class="fas <?php echo $getSortIcon('score'); ?>"></i>
                            </a>
                        </th>
                        <th style="width: 150px;"><?php echo htmlspecialchars(__('actions')); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($messages as $msg): ?>
                        <?php
                        $msgId = $msg['id'];
                        $sender = decodeMimeHeader($msg['sender']);
                        $senderEmail = extractEmailAddress($sender);
                        $senderEmailKey = $senderEmail ? strtolower($senderEmail) : '';
                        $isRandomSender = $senderEmail ? isLikelyRandomEmail($senderEmail) : false;
                        $recipients = decodeMimeHeader($msg['recipients']);
                        $subject = decodeMimeHeader($msg['subject']) ?: __('msg_no_subject');
                        $score = round($msg['score'], 2);
                        $action = strtolower(trim($msg['action'] ?? ''));
                        $hostname = $msg['hostname'] ?? '-';

                        // Parse symbols from JSON
                        $symbols = $msg['symbols'] ?? '';
                        $parsedSymbols = [];

                        $hasVirusSymbol = false;
                        if (!empty($symbols)) {
                            $symbolsData = json_decode($symbols, true);

                            if (is_array($symbolsData)) {
                                foreach ($symbolsData as $symbol) {
                                    if (isset($symbol['name']) && isset($symbol['score'])) {
                                        $parsedSymbols[] = [
                                            'name' => $symbol['name'],
                                            'score' => floatval($symbol['score'])
                                        ];
                                        if (stripos($symbol['name'], 'VIRUS') !== false) {
                                            $hasVirusSymbol = true;
                                        }
                                    }
                                }

                        // Sort by score descending
                                usort($parsedSymbols, function($a, $b) {
                                    return $b['score'] <=> $a['score'];
                                });
                            }
                        }
                        if (!$hasVirusSymbol && stripos($symbols, 'VIRUS') !== false) {
                            $hasVirusSymbol = true;
                        }
                        $timestamp = date('d.m. H:i', strtotime($msg['timestamp']));

                        // Score class based on action (fallback to score)
                        $actionScoreClass = '';
                        switch ($action) {
                            case 'no action':
                                $actionScoreClass = 'score-action-no-action';
                                break;
                            case 'greylist':
                                $actionScoreClass = 'score-action-greylist';
                                break;
                            case 'add header':
                                $actionScoreClass = 'score-action-add-header';
                                break;
                            case 'rewrite subject':
                                $actionScoreClass = 'score-action-rewrite-subject';
                                break;
                            case 'reject':
                                $actionScoreClass = 'score-action-reject';
                                break;
                        }
                        if ($score >= 15) {
                            $scoreClass = 'score-high';
                        } elseif ($score >= 6) {
                            $scoreClass = 'score-medium';
                        } else {
                            $scoreClass = 'score-low';
                        }
                        $scoreClass = $actionScoreClass ?: $scoreClass;

                        // State class for row coloring
                        $stateClass = '';
                        switch ((int)$msg['state']) {
                            case 0: $stateClass = 'state-quarantined'; break;
                            case 1: $stateClass = 'state-learned-ham'; break;
                            case 2: $stateClass = 'state-learned-spam'; break;
                            case 3: $stateClass = 'state-released'; break;
                        }
                        $virusClass = $hasVirusSymbol ? 'has-virus' : '';
                        ?>
                        <tr class="message-row <?php echo trim($stateClass . ' ' . $virusClass); ?>" id="row_<?php echo $msgId; ?>">
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
                            <td class="subject-field">
                                <?php echo htmlspecialchars(truncateText($subject, 70)); ?>
                            </td>
                            <td class="hostname-field">
                                <?php echo htmlspecialchars($hostname); ?>
                            </td>
                            <td class="text-right no-wrap">
                                <?php echo htmlspecialchars(formatMessageSize((int)($msg['size_bytes'] ?? 0))); ?>
                            </td>
                            <td class="text-center score-cell">
                                <span class="score-badge <?php echo $scoreClass; ?>">
                                    <?php echo $score; ?>

                                    <?php if (!empty($parsedSymbols)): ?>
                                    <div class="symbols-popup">
                                        <div class="symbols-popup-header">
                                            <i class="fas fa-list-ul"></i> <?php echo htmlspecialchars(__('msg_symbols')); ?> (<?php echo count($parsedSymbols); ?>)
                                        </div>
                                        <div class="symbols-grid">
                                            <?php foreach ($parsedSymbols as $sym): 
                                                $symScore = $sym['score'];
                                                $bgcolor = ($symScore >= 1) ? '#e74c3c' : (($symScore > 0) ? '#f39c12' : (($symScore < 0) ? '#27ae60' : '#95a5a6'));
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
                            <td class="text-center">
                                <div class="action-controls">
                                    <a href="view.php?id=<?php echo $msgId; ?>" class="action-btn view-btn" title="<?php echo htmlspecialchars(__('msg_view_details')); ?>">
                                        <i class="fas fa-eye"></i>
                                    </a>
                                    <form method="POST" action="operations.php" style="display: inline;">
                                        <input type="hidden" name="message_ids" value="<?php echo $msgId; ?>">
                                        <input type="hidden" name="operation" value="learn_spam">
                                        <input type="hidden" name="return_url" value="index.php">
                                        <button type="submit" class="action-btn learn-spam-btn" title="<?php echo htmlspecialchars(__('msg_learn_spam')); ?>">
                                            <i class="fas fa-ban"></i>
                                        </button>
                                    </form>
                                    <form method="POST" action="operations.php" style="display: inline;">
                                        <input type="hidden" name="message_ids" value="<?php echo $msgId; ?>">
                                        <input type="hidden" name="operation" value="learn_ham">
                                        <input type="hidden" name="return_url" value="index.php">
                                        <button type="submit" class="action-btn learn-ham-btn" title="<?php echo htmlspecialchars(__('msg_learn_ham')); ?>">
                                            <i class="fas fa-check"></i>
                                        </button>
                                    </form>
                                    <form method="POST" action="operations.php" style="display: inline;">
                                        <input type="hidden" name="message_ids" value="<?php echo $msgId; ?>">
                                        <input type="hidden" name="operation" value="release">
                                        <input type="hidden" name="return_url" value="index.php">
                                        <button type="submit" class="action-btn release-btn" title="<?php echo htmlspecialchars(__('msg_release')); ?>">
                                            <i class="fas fa-paper-plane"></i>
                                        </button>
                                    </form>
                                    <form method="POST" action="operations.php" style="display: inline;" onsubmit="return confirm('<?php echo htmlspecialchars(__('confirm_delete_message')); ?>');">
                                        <input type="hidden" name="message_ids" value="<?php echo $msgId; ?>">
                                        <input type="hidden" name="operation" value="delete">
                                        <input type="hidden" name="return_url" value="index.php">
                                        <button type="submit" class="action-btn delete-btn" title="<?php echo htmlspecialchars(__('msg_delete')); ?>">
                                            <i class="fas fa-trash"></i>
                                        </button>
                                    </form>
                                </div>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>

             <!-- Pagination -->
            <?php if ($totalPages > 1): ?>
                <div class="pagination">
                    <?php if ($page > 1): ?>
                        <a href="?page=<?php echo $page - 1; ?>&<?php echo http_build_query(array_diff_key($_GET, ['page' => '', 'reset_page' => ''])); ?>" class="page-link">
                            <i class="fas fa-chevron-left"></i> <?php echo htmlspecialchars(__('pagination_previous')); ?>
                        </a>
                    <?php endif; ?>

                    <?php
                    $start = max(1, $page - 3);
                    $end = min($totalPages, $page + 3);
                    for ($i = $start; $i <= $end; $i++):
                        $activeClass = ($i == $page) ? 'active' : '';
                    ?>
                        <a href="?page=<?php echo $i; ?>&<?php echo http_build_query(array_diff_key($_GET, ['page' => '', 'reset_page' => ''])); ?>" 
                           class="page-link <?php echo $activeClass; ?>">
                            <?php echo $i; ?>
                        </a>
                    <?php endfor; ?>

                    <?php if ($page < $totalPages): ?>
                        <a href="?page=<?php echo $page + 1; ?>&<?php echo http_build_query(array_diff_key($_GET, ['page' => '', 'reset_page' => ''])); ?>" class="page-link">
                            <?php echo htmlspecialchars(__('pagination_next')); ?> <i class="fas fa-chevron-right"></i>
                        </a>
                    <?php endif; ?>
                </div>
            <?php endif; ?>
        <?php endif; ?>
    </div>

    <!-- Preview Tooltip -->
    <div id="previewTooltip" class="preview-tooltip">
        <div class="preview-loading">
            <i class="fas fa-spinner fa-spin"></i> <?php echo htmlspecialchars(__('preview_loading')); ?>
        </div>
    </div>

    <script>
    // Preview tooltip functionality
    let previewFormat = 'text';
    let previewTimeout = null;
    let activeRequest = null;

    function loadPreviewFormat() {
        const saved = sessionStorage.getItem('previewFormat');
        if (saved) {
            previewFormat = saved;
            const checkbox = document.getElementById('htmlPreviewToggle');
            if (checkbox) {
                checkbox.checked = (previewFormat === 'html');
            }
        }
    }

    function toggleHtmlPreview(enabled) {
        previewFormat = enabled ? 'html' : 'text';
        sessionStorage.setItem('previewFormat', previewFormat);
        hidePreview();
    }

    document.addEventListener('DOMContentLoaded', function() {
        loadPreviewFormat();

        const rows = document.querySelectorAll('.message-row');
        const tooltip = document.getElementById('previewTooltip');

        rows.forEach(function(row) {
            const subjectCell = row.querySelector('.subject-field');
            if (!subjectCell) return;

            const msgId = row.id.replace('row_', '');

            subjectCell.addEventListener('mouseenter', function(e) {
                previewTimeout = setTimeout(function() {
                    showPreview(msgId, e.clientX, e.clientY);
                }, 500);
            });

            subjectCell.addEventListener('mouseleave', function() {
                clearTimeout(previewTimeout);
                hidePreview();
            });

            subjectCell.addEventListener('mousemove', function(e) {
                if (tooltip.classList.contains('active')) {
                    positionTooltip(e.clientX, e.clientY);
                }
            });
        });

        tooltip.addEventListener('mouseenter', function() {
            clearTimeout(previewTimeout);
        });

        tooltip.addEventListener('mouseleave', function() {
            hidePreview();
        });

        window.addEventListener('scroll', function() {
            if (tooltip.classList.contains('active')) {
                hidePreview();
            }
        }, { passive: true });
    });

    function showPreview(msgId, x, y) {
        const tooltip = document.getElementById('previewTooltip');

        if (activeRequest) {
            activeRequest.abort();
        }

        tooltip.innerHTML = '<div class="preview-loading"><i class="fas fa-spinner fa-spin"></i> <?php echo htmlspecialchars(__('preview_loading')); ?></div>';
        tooltip.classList.add('active');
        positionTooltip(x, y);

        activeRequest = new XMLHttpRequest();
        activeRequest.open('GET', 'api_message_preview.php?id=' + encodeURIComponent(msgId) + '&format=' + previewFormat, true);

        activeRequest.onload = function() {
            if (activeRequest.status === 200) {
                try {
                    const data = JSON.parse(activeRequest.responseText);

                    if (data.success) {
                        renderPreview(data);
                    } else {
                        tooltip.innerHTML = '<div class="preview-error"><?php echo htmlspecialchars(__('preview_error')); ?>: ' + escapeHtml(data.error) + '</div>';
                    }
                } catch (e) {
                    tooltip.innerHTML = '<div class="preview-error"><?php echo htmlspecialchars(__('preview_parse_error')); ?></div>';
                }
            } else {
                tooltip.innerHTML = '<div class="preview-error"><?php echo htmlspecialchars(__('preview_load_failed')); ?></div>';
            }
            activeRequest = null;
        };

        activeRequest.onerror = function() {
            tooltip.innerHTML = '<div class="preview-error"><?php echo htmlspecialchars(__('preview_network_error')); ?></div>';
            activeRequest = null;
        };

        activeRequest.send();
    }

    function renderPreview(data) {
        const tooltip = document.getElementById('previewTooltip');
        const contentClass = data.is_html ? 'preview-content html-mode' : 'preview-content';

        let formatIndicator = '';
        if (data.is_html) {
            formatIndicator = `<span style="font-size: 10px; color: #007bff; margin-left: 5px;">
                <i class="fas fa-code"></i> <?php echo htmlspecialchars(__('preview_mode_html')); ?>
            </span>`;
        } else if (data.has_html) {
            formatIndicator = `<span style="font-size: 10px; color: #6c757d; margin-left: 5px;">
                <i class="fas fa-align-left"></i> <?php echo htmlspecialchars(__('preview_mode_text')); ?>
            </span>`;
        }

        tooltip.innerHTML = `
            <div class="preview-header">
                <h4><i class="fas fa-envelope"></i> <?php echo htmlspecialchars(__('preview_message_title')); ?> ${formatIndicator}</h4>
                <div class="preview-meta"><strong><?php echo htmlspecialchars(__('from')); ?>:</strong> ${escapeHtml(data.sender)}</div>
                <div class="preview-meta"><strong><?php echo htmlspecialchars(__('subject')); ?>:</strong> ${escapeHtml(data.subject)}</div>
                <div class="preview-meta"><strong><?php echo htmlspecialchars(__('time')); ?>:</strong> ${escapeHtml(data.timestamp)} | <strong><?php echo htmlspecialchars(__('msg_score')); ?>:</strong> ${data.score}</div>
            </div>
            <div class="${contentClass}">${data.is_html ? data.preview : escapeHtml(data.preview)}</div>
        `;
    }

    function hidePreview() {
        const tooltip = document.getElementById('previewTooltip');
        tooltip.classList.remove('active');

        if (activeRequest) {
            activeRequest.abort();
            activeRequest = null;
        }
    }

    function positionTooltip(x, y) {
        const tooltip = document.getElementById('previewTooltip');
        const offset = 15;
        const padding = 10;

        const viewportWidth = window.innerWidth;
        const viewportHeight = window.innerHeight;

        let left = x + offset;
        let top = y + offset;

        tooltip.style.opacity = '0';
        tooltip.style.display = 'block';
        const rect = tooltip.getBoundingClientRect();
        tooltip.style.opacity = '';

        if (left + rect.width > viewportWidth - padding) {
            left = x - rect.width - offset;
        }

        if (top + rect.height > viewportHeight - padding) {
            top = y - rect.height - offset;
        }

        left = Math.max(padding, Math.min(left, viewportWidth - rect.width - padding));
        top = Math.max(padding, Math.min(top, viewportHeight - rect.height - padding));

        tooltip.style.left = left + 'px';
        tooltip.style.top = top + 'px';
        tooltip.style.display = '';
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
