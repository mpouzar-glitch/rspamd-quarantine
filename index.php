<?php
/*
 * Version: 2.0.0
 * Author: Martin Pouzar
 * License: GNU General Public License v3.0
 */
/**
 * Rspamd Quarantine - Main Index
 * Updated: Compact table, state colors, preview modal, icon-only buttons, clickable emails
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
$canDeleteMessages = checkPermission('domain_admin');

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
                        <th style="width: 120px;">
                            <?php echo htmlspecialchars(__('status')); ?>
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
                        $actionLabel = $msg['action'] ?? '-';
                        $hostname = $msg['hostname'] ?? '-';

                        // Parse symbols from JSON
                        $symbols = $msg['symbols'] ?? '';
                        $parsedSymbols = [];

                        $virusSymbols = ['ESET_VIRUS', 'CLAM_VIRUS'];
                        $badExtensionSymbols = ['BAD_FILE_EXT', 'ARCHIVE_WITH_EXECUTABLE', 'BAD_ATTACHMENT_EXT', 'BAD_ATTACHEMENT_EXT'];
                        $blacklistSymbols = ['BLACKLIST_IP', 'BLACKLIST_EMAIL_SMTP', 'BLACKLIST_EMAIL_MIME'];
                        $whitelistSymbols = ['WHITELIST_IP', 'WHITELIST_EMAIL_MIME', 'WHITELIST_EMAIL_SMTP'];
                        $hasVirusSymbol = false;
                        $hasBadExtensionSymbol = false;
                        $hasBlacklistSymbol = false;
                        $hasWhitelistSymbol = false;
                        if (!empty($symbols)) {
                            $symbolsData = json_decode($symbols, true);

                            if (is_array($symbolsData)) {
                                foreach ($symbolsData as $symbol) {
                                    if (isset($symbol['name']) && isset($symbol['score'])) {
                                        $parsedSymbols[] = [
                                            'name' => $symbol['name'],
                                            'score' => floatval($symbol['score'])
                                        ];
                                        if (in_array($symbol['name'], $virusSymbols, true)) {
                                            $hasVirusSymbol = true;
                                        }
                                        if (in_array($symbol['name'], $badExtensionSymbols, true)) {
                                            $hasBadExtensionSymbol = true;
                                        }
                                        if (in_array($symbol['name'], $blacklistSymbols, true)) {
                                            $hasBlacklistSymbol = true;
                                        }
                                        if (in_array($symbol['name'], $whitelistSymbols, true)) {
                                            $hasWhitelistSymbol = true;
                                        }
                                    }
                                }

                                // Sort by score descending
                                usort($parsedSymbols, function($a, $b) {
                                    return $b['score'] <=> $a['score'];
                                });
                            }
                        }
                        if (!empty($symbols)) {
                            foreach ($virusSymbols as $virusSymbol) {
                                if (stripos($symbols, $virusSymbol) !== false) {
                                    $hasVirusSymbol = true;
                                    break;
                                }
                            }
                        }
                        if (!$hasBadExtensionSymbol && !empty($symbols)) {
                            foreach ($badExtensionSymbols as $badExtensionSymbol) {
                                if (stripos($symbols, $badExtensionSymbol) !== false) {
                                    $hasBadExtensionSymbol = true;
                                    break;
                                }
                            }
                        }
                        if (!$hasBlacklistSymbol && !empty($symbols)) {
                            foreach ($blacklistSymbols as $blacklistSymbol) {
                                if (stripos($symbols, $blacklistSymbol) !== false) {
                                    $hasBlacklistSymbol = true;
                                    break;
                                }
                            }
                        }
                        if (!$hasWhitelistSymbol && !empty($symbols)) {
                            foreach ($whitelistSymbols as $whitelistSymbol) {
                                if (stripos($symbols, $whitelistSymbol) !== false) {
                                    $hasWhitelistSymbol = true;
                                    break;
                                }
                            }
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
                        $statusLabel = '';
                        $statusClass = '';
                        if ($hasVirusSymbol) {
                            $statusLabel = 'virus';
                            $statusClass = 'status-virus';
                        } elseif ($hasBadExtensionSymbol) {
                            $statusLabel = 'příloha';
                            $statusClass = 'status-bad-extension';
                        } elseif ($hasBlacklistSymbol) {
                            $statusLabel = 'blacklist';
                            $statusClass = 'status-blacklist';
                        } elseif ($hasWhitelistSymbol) {
                            $statusLabel = 'whitelist';
                            $statusClass = 'status-whitelist';
                        }
                        $virusClass = $hasVirusSymbol ? 'has-virus' : '';
                        $formattedSize = formatMessageSize((int)($msg['size_bytes'] ?? 0));
                        ?>
                        <tr class="message-row <?php echo trim($stateClass . ' ' . $virusClass . ' ' . $statusClass); ?>" id="row_<?php echo $msgId; ?>"
                            data-sender="<?php echo htmlspecialchars($sender, ENT_QUOTES); ?>"
                            data-recipients="<?php echo htmlspecialchars($recipients, ENT_QUOTES); ?>"
                            data-subject="<?php echo htmlspecialchars($subject, ENT_QUOTES); ?>"
                            data-timestamp="<?php echo htmlspecialchars($timestamp, ENT_QUOTES); ?>"
                            data-score="<?php echo htmlspecialchars((string)$score, ENT_QUOTES); ?>"
                            data-hostname="<?php echo htmlspecialchars($hostname, ENT_QUOTES); ?>"
                            data-size="<?php echo htmlspecialchars($formattedSize, ENT_QUOTES); ?>"
                            data-action="<?php echo htmlspecialchars($actionLabel, ENT_QUOTES); ?>"
                        >
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
                                <button type="button" class="subject-preview-btn email-link message-popup-trigger" data-message-id="<?php echo $msgId; ?>">
                                    <?php echo htmlspecialchars(truncateText($subject, 70)); ?>
                                </button>
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
                            <td class="status-field">
                                <?php if (!empty($statusLabel)): ?>
                                    <span class="status-badge <?php echo htmlspecialchars($statusClass); ?>">
                                        <?php echo htmlspecialchars($statusLabel); ?>
                                    </span>
                                <?php else: ?>
                                    <span class="status-badge status-neutral">-</span>
                                <?php endif; ?>
                            </td>
                            <td class="hostname-field">
                                <?php echo htmlspecialchars($hostname); ?>
                            </td>
                            <td class="text-right no-wrap">
                                <?php echo htmlspecialchars($formattedSize); ?>
                            </td>
                            <td class="text-center score-cell">
                                <span class="score-badge <?php echo $scoreClass; ?>">
                                    <?php echo $score; ?>
                                    <?php if ($hasVirusSymbol): ?>
                                        <i class="fas fa-biohazard virus-icon" title="<?php echo htmlspecialchars(__('filter_virus')); ?>"></i>
                                    <?php endif; ?>
                                    <?php if ($hasBadExtensionSymbol): ?>
                                        <i class="fas fa-paperclip bad-attachment-icon" title="<?php echo htmlspecialchars(__('filter_dangerous_attachment')); ?>"></i>
                                    <?php endif; ?>

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
                                    <button type="button" class="action-btn view-btn message-popup-trigger" data-message-id="<?php echo $msgId; ?>" title="<?php echo htmlspecialchars(__('msg_view_details')); ?>">
                                        <i class="fas fa-eye"></i>
                                    </button>
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
                                    <?php if ($canDeleteMessages): ?>
                                        <form method="POST" action="operations.php" style="display: inline;" onsubmit="return confirm('<?php echo htmlspecialchars(__('confirm_delete_message')); ?>');">
                                            <input type="hidden" name="message_ids" value="<?php echo $msgId; ?>">
                                            <input type="hidden" name="operation" value="delete">
                                            <input type="hidden" name="return_url" value="index.php">
                                            <button type="submit" class="action-btn delete-btn" title="<?php echo htmlspecialchars(__('msg_delete')); ?>">
                                                <i class="fas fa-trash"></i>
                                            </button>
                                        </form>
                                    <?php endif; ?>
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

    const popupStrings = {
        title: <?php echo json_encode(__('preview_message_title')); ?>,
        sender: <?php echo json_encode(__('msg_sender')); ?>,
        recipient: <?php echo json_encode(__('msg_recipient')); ?>,
        subject: <?php echo json_encode(__('msg_subject')); ?>,
        time: <?php echo json_encode(__('time')); ?>,
        score: <?php echo json_encode(__('msg_score')); ?>,
        hostname: <?php echo json_encode(__('hostname')); ?>,
        size: <?php echo json_encode(__('size')); ?>,
        action: <?php echo json_encode(__('action')); ?>,
        loading: <?php echo json_encode(__('preview_loading')); ?>,
        errorLabel: <?php echo json_encode(__('preview_error')); ?>,
        parseError: <?php echo json_encode(__('preview_parse_error')); ?>,
        loadFailed: <?php echo json_encode(__('preview_load_failed')); ?>,
        networkError: <?php echo json_encode(__('preview_network_error')); ?>,
        previewModeHtml: <?php echo json_encode(__('preview_mode_html')); ?>,
        previewModeText: <?php echo json_encode(__('preview_mode_text')); ?>
    };

    document.addEventListener('DOMContentLoaded', function() {
        document.querySelectorAll('.message-popup-trigger').forEach((button) => {
            button.addEventListener('click', () => {
                openMessagePopup(button.dataset.messageId);
            });
        });
    });

    function openMessagePopup(msgId) {
        if (!msgId) {
            return;
        }

        const row = document.getElementById('row_' + msgId);
        if (!row) {
            return;
        }

        const meta = {
            sender: row.dataset.sender || '',
            recipients: row.dataset.recipients || '',
            subject: row.dataset.subject || '',
            timestamp: row.dataset.timestamp || '',
            score: row.dataset.score || '',
            hostname: row.dataset.hostname || '',
            size: row.dataset.size || '',
            action: row.dataset.action || ''
        };

        const popup = window.open('', 'message_' + msgId, 'width=1100,height=750,resizable=yes,scrollbars=yes');
        if (!popup) {
            return;
        }

        popup.document.open();
        popup.document.write(buildPopupHtml(meta));
        popup.document.close();

        const request = new XMLHttpRequest();
        request.open('GET', 'api_message_preview.php?id=' + encodeURIComponent(msgId) + '&format=auto', true);

        request.onload = function() {
            if (request.status === 200) {
                try {
                    const data = JSON.parse(request.responseText);
                    if (data.success) {
                        renderPopupPreview(popup, data);
                    } else {
                        setPopupError(popup, popupStrings.errorLabel + ': ' + (data.error || ''));
                    }
                } catch (e) {
                    setPopupError(popup, popupStrings.parseError);
                }
            } else {
                setPopupError(popup, popupStrings.loadFailed);
            }
        };

        request.onerror = function() {
            setPopupError(popup, popupStrings.networkError);
        };

        request.send();
    }

    function buildPopupHtml(meta) {
        const safeMeta = {
            sender: escapeHtml(meta.sender),
            recipients: escapeHtml(meta.recipients),
            subject: escapeHtml(meta.subject),
            timestamp: escapeHtml(meta.timestamp),
            score: escapeHtml(meta.score),
            hostname: escapeHtml(meta.hostname),
            size: escapeHtml(meta.size),
            action: escapeHtml(meta.action)
        };

        return `
<!DOCTYPE html>
<html lang="<?php echo htmlspecialchars(currentLang()); ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${popupStrings.title}</title>
    <style>
        * { box-sizing: border-box; }
        body {
            margin: 0;
            font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f7fa;
            color: #2c3e50;
        }
        .popup-container {
            display: flex;
            height: 100vh;
        }
        .popup-sidebar {
            width: 36%;
            min-width: 280px;
            background: #ffffff;
            border-right: 1px solid #e1e4ea;
            padding: 24px;
            overflow-y: auto;
        }
        .popup-title {
            margin: 0 0 16px 0;
            font-size: 20px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .meta-item {
            margin-bottom: 14px;
            display: flex;
            flex-direction: column;
            gap: 4px;
        }
        .meta-label {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.03em;
            color: #7f8c8d;
        }
        .meta-value {
            font-size: 14px;
            font-weight: 600;
            word-break: break-word;
        }
        .popup-preview {
            flex: 1;
            padding: 24px;
            display: flex;
            flex-direction: column;
            gap: 16px;
        }
        .preview-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 8px;
        }
        .preview-title {
            font-size: 18px;
            font-weight: 600;
        }
        .preview-format {
            font-size: 12px;
            color: #7f8c8d;
            background: #ecf0f1;
            padding: 4px 8px;
            border-radius: 999px;
        }
        .preview-body {
            flex: 1;
            background: #ffffff;
            border: 1px solid #e1e4ea;
            border-radius: 10px;
            padding: 16px;
            overflow: auto;
        }
        .preview-loading {
            font-size: 14px;
            color: #7f8c8d;
        }
        .preview-error {
            color: #c0392b;
            font-weight: 600;
        }
        .preview-iframe {
            width: 100%;
            height: 100%;
            border: none;
        }
        pre {
            white-space: pre-wrap;
            word-break: break-word;
            font-family: "Courier New", monospace;
        }
    </style>
</head>
<body>
    <div class="popup-container">
        <aside class="popup-sidebar">
            <div class="popup-title"><?php echo htmlspecialchars(__('preview_message_title')); ?></div>
            <div class="meta-item">
                <span class="meta-label">${popupStrings.sender}</span>
                <span class="meta-value" id="metaSender">${safeMeta.sender}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">${popupStrings.recipient}</span>
                <span class="meta-value" id="metaRecipients">${safeMeta.recipients}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">${popupStrings.subject}</span>
                <span class="meta-value" id="metaSubject">${safeMeta.subject}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">${popupStrings.time}</span>
                <span class="meta-value" id="metaTimestamp">${safeMeta.timestamp}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">${popupStrings.score}</span>
                <span class="meta-value" id="metaScore">${safeMeta.score}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">${popupStrings.hostname}</span>
                <span class="meta-value" id="metaHostname">${safeMeta.hostname}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">${popupStrings.size}</span>
                <span class="meta-value" id="metaSize">${safeMeta.size}</span>
            </div>
            <div class="meta-item">
                <span class="meta-label">${popupStrings.action}</span>
                <span class="meta-value" id="metaAction">${safeMeta.action}</span>
            </div>
        </aside>
        <section class="popup-preview">
            <div class="preview-header">
                <div class="preview-title"><?php echo htmlspecialchars(__('preview_message_title')); ?></div>
                <div class="preview-format" id="previewFormat"></div>
            </div>
            <div class="preview-body" id="previewBody">
                <div class="preview-loading">${popupStrings.loading}</div>
            </div>
        </section>
    </div>
</body>
</html>`;
    }

    function renderPopupPreview(popup, data) {
        if (!popup || popup.closed) {
            return;
        }

        const doc = popup.document;
        const formatEl = doc.getElementById('previewFormat');
        if (formatEl) {
            if (data.is_html) {
                formatEl.textContent = popupStrings.previewModeHtml;
            } else if (data.has_html) {
                formatEl.textContent = popupStrings.previewModeText;
            } else {
                formatEl.textContent = '';
            }
        }

        const metaUpdates = {
            metaSender: data.sender,
            metaSubject: data.subject,
            metaTimestamp: data.timestamp,
            metaScore: data.score
        };
        Object.keys(metaUpdates).forEach((key) => {
            const el = doc.getElementById(key);
            if (el && metaUpdates[key] !== undefined) {
                el.textContent = metaUpdates[key];
            }
        });

        const previewBody = doc.getElementById('previewBody');
        if (!previewBody) {
            return;
        }

        previewBody.innerHTML = '';

        if (data.is_html) {
            const iframe = doc.createElement('iframe');
            iframe.className = 'preview-iframe';
            iframe.setAttribute('sandbox', '');
            iframe.setAttribute('referrerpolicy', 'no-referrer');
            iframe.srcdoc = data.preview;
            previewBody.appendChild(iframe);
        } else {
            const pre = doc.createElement('pre');
            pre.textContent = data.preview;
            previewBody.appendChild(pre);
        }
    }

    function setPopupError(popup, message) {
        if (!popup || popup.closed) {
            return;
        }
        const previewBody = popup.document.getElementById('previewBody');
        if (!previewBody) {
            return;
        }
        previewBody.innerHTML = '<div class="preview-error">' + escapeHtml(message) + '</div>';
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
