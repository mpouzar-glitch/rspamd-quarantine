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
$isAdmin = checkPermission('admin');

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
    'country' => 'country',
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
$listedEmailRegexMatches = ['whitelist' => [], 'blacklist' => []];
$listedSubjectMatches = ['whitelist' => [], 'blacklist' => []];
if ($canManageMaps && !empty($messages)) {
    $senderEmails = [];
    $subjectValues = [];
    foreach ($messages as $message) {
        $senderEmail = extractEmailAddress(decodeMimeHeader($message['sender']));
        if (!empty($senderEmail)) {
            $senderEmails[] = $senderEmail;
        }
        $subjectValue = trim((string)decodeMimeHeader($message['subject']));
        if ($subjectValue !== '') {
            $subjectValues[] = $subjectValue;
        }
    }
    $listedEmails = getEmailMapStatus($db, $senderEmails);
    $listedEmailRegexMatches = getRegexMapMatches($db, $senderEmails, 'email_regex');
    $listedSubjectMatches = getRegexMapMatches($db, $subjectValues, 'subject');
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
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/flag-icons/6.6.6/css/flag-icons.min.css">
    <link rel="stylesheet" href="css/style.css">
    <link rel="stylesheet" href="css/stats-inline.css">
    <link rel="stylesheet" href="css/bulk.css">
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
            'show_action' => true,
            'show_score_min' => false,
            'show_score_max' => false,
            'show_dates' => true,
            'show_sender' => true,
            'show_recipient' => true,
            'show_state' => true,
            'show_ip' => false,
            'show_auth_user' => false,
            'show_country' => true,
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
        <div class="table-container">
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
                        ['key' => 'hostname', 'style' => 'width: 80px;'],
                        ['key' => 'country', 'style' => 'width: 20px;'],
                        ['key' => 'size', 'style' => 'width: 90px;'],
                        ['key' => 'score', 'style' => 'width: 60px;'],
                        ['key' => 'status', 'style' => 'col-status'],
                        ['key' => 'actions', 'style' => 'width: 150px;'],
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
                        $isRandomSender = $senderEmail ? isLikelyRandomEmail($senderEmail) : false;
                        $recipients = decodeMimeHeader($msg['recipients']);
                        $subject = decodeMimeHeader($msg['subject']) ?: __('msg_no_subject');
                        $score = round($msg['score'], 2);
                        $action = strtolower(trim($msg['action'] ?? ''));
                        $hostname = $msg['hostname'] ?? '-';
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
                        $isReleaseRestricted = !$isAdmin && ($hasVirusSymbol || $hasBadAttachmentSymbol);

                        // State class for row coloring
                        $stateClass = getMessageStateClass((int)$msg['state']);
                        $statusRowClass = getStatusRowClass($statusSymbolMatches);
                        $virusClass = $hasVirusSymbol ? 'has-virus' : '';
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
                                    $whitelistEntryValue = $listedEmails['whitelist'][$senderEmailKey] ?? null;
                                    $whitelistEntryType = $whitelistEntryValue !== null ? 'email' : null;
                                    if ($whitelistEntryValue === null && isset($listedEmailRegexMatches['whitelist'][$senderEmailKey])) {
                                        $whitelistEntryValue = $listedEmailRegexMatches['whitelist'][$senderEmailKey];
                                        $whitelistEntryType = 'email_regex';
                                    }
                                    $blacklistEntryValue = $listedEmails['blacklist'][$senderEmailKey] ?? null;
                                    $blacklistEntryType = $blacklistEntryValue !== null ? 'email' : null;
                                    if ($blacklistEntryValue === null && isset($listedEmailRegexMatches['blacklist'][$senderEmailKey])) {
                                        $blacklistEntryValue = $listedEmailRegexMatches['blacklist'][$senderEmailKey];
                                        $blacklistEntryType = 'email_regex';
                                    }
                                    $isWhitelisted = $whitelistEntryValue !== null;
                                    $isBlacklisted = $blacklistEntryValue !== null;
                                    ?>
                                    <span class="sender-actions">
                                        <?php if ($isWhitelisted): ?>
                                            <form method="POST" action="map_quick_add.php" class="sender-action-form" onsubmit="return confirm('<?php echo htmlspecialchars(__('maps_confirm_delete')); ?>');">
                                                <input type="hidden" name="action" value="delete">
                                                <input type="hidden" name="list_type" value="whitelist">
                                                <input type="hidden" name="entry_type" value="<?php echo htmlspecialchars($whitelistEntryType); ?>">
                                                <input type="hidden" name="entry_value" value="<?php echo htmlspecialchars($whitelistEntryValue); ?>">
                                                <input type="hidden" name="return_url" value="<?php echo htmlspecialchars($returnUrl); ?>">
                                                <button type="submit" class="sender-action-btn blacklist-btn is-listed" title="<?php echo htmlspecialchars(__('maps_remove_whitelist_sender')); ?>">
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
                                                <input type="hidden" name="entry_type" value="<?php echo htmlspecialchars($blacklistEntryType); ?>">
                                                <input type="hidden" name="entry_value" value="<?php echo htmlspecialchars($blacklistEntryValue); ?>">
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
                                <button type="button" class="subject-preview-btn email-link" data-message-id="<?php echo $msgId; ?>" aria-label="<?php echo htmlspecialchars(__('preview_message_title')); ?>">
                                    <?php echo htmlspecialchars(truncateText($subject, 70)); ?>
                                </button>
                                <?php if ($canManageMaps && !empty(trim($subject))): ?>
                                    <?php
                                    $subjectKey = trim($subject);
                                    $subjectWhitelistEntry = $listedSubjectMatches['whitelist'][$subjectKey] ?? null;
                                    $subjectBlacklistEntry = $listedSubjectMatches['blacklist'][$subjectKey] ?? null;
                                    ?>
                                    <span class="sender-actions subject-actions">
                                        <?php if ($subjectWhitelistEntry !== null): ?>
                                            <form method="POST" action="map_quick_add.php" class="sender-action-form" onsubmit="return confirm('<?php echo htmlspecialchars(__('maps_confirm_delete')); ?>');">
                                                <input type="hidden" name="action" value="delete">
                                                <input type="hidden" name="list_type" value="whitelist">
                                                <input type="hidden" name="entry_type" value="subject">
                                                <input type="hidden" name="entry_value" value="<?php echo htmlspecialchars($subjectWhitelistEntry); ?>">
                                                <input type="hidden" name="return_url" value="<?php echo htmlspecialchars($returnUrl); ?>">
                                                <button type="submit" class="sender-action-btn blacklist-btn is-listed" title="<?php echo htmlspecialchars(__('maps_remove_whitelist_subject')); ?>">
                                                    <i class="fas fa-xmark"></i>
                                                </button>
                                            </form>
                                        <?php else: ?>
                                            <button type="button" class="sender-action-btn whitelist-btn subject-map-btn" data-list-type="whitelist" data-subject="<?php echo htmlspecialchars($subject, ENT_QUOTES); ?>" title="<?php echo htmlspecialchars(__('maps_add_whitelist_subject')); ?>">
                                                <i class="fas fa-shield-alt"></i>
                                            </button>
                                        <?php endif; ?>
                                        <?php if ($subjectBlacklistEntry !== null): ?>
                                            <form method="POST" action="map_quick_add.php" class="sender-action-form" onsubmit="return confirm('<?php echo htmlspecialchars(__('maps_confirm_delete')); ?>');">
                                                <input type="hidden" name="action" value="delete">
                                                <input type="hidden" name="list_type" value="blacklist">
                                                <input type="hidden" name="entry_type" value="subject">
                                                <input type="hidden" name="entry_value" value="<?php echo htmlspecialchars($subjectBlacklistEntry); ?>">
                                                <input type="hidden" name="return_url" value="<?php echo htmlspecialchars($returnUrl); ?>">
                                                <button type="submit" class="sender-action-btn blacklist-btn is-listed" title="<?php echo htmlspecialchars(__('maps_remove_blacklist_subject')); ?>">
                                                    <i class="fas fa-xmark"></i>
                                                </button>
                                            </form>
                                        <?php else: ?>
                                            <button type="button" class="sender-action-btn blacklist-btn subject-map-btn" data-list-type="blacklist" data-subject="<?php echo htmlspecialchars($subject, ENT_QUOTES); ?>" title="<?php echo htmlspecialchars(__('maps_add_blacklist_subject')); ?>">
                                                <i class="fas fa-ban"></i>
                                            </button>
                                        <?php endif; ?>
                                    </span>
                                <?php endif; ?>
                            </td>
                            <td class="hostname-field">
                                <?php echo htmlspecialchars($hostname); ?>
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
                                            <i class="fas fa-list-ul"></i> <?php echo htmlspecialchars(__('msg_symbols')); ?> (<?php echo count($parsedSymbols); ?>)
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
                                        <button type="submit" class="action-btn release-btn" title="<?php echo htmlspecialchars(__('msg_release')); ?>" <?php echo $isReleaseRestricted ? 'disabled' : ''; ?>>
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
        </div>

             <!-- Pagination -->
            <?php
            $paginationQuery = array_diff_key($_GET, ['page' => '', 'reset_page' => '']);
            echo renderPagination($page, $totalPages, $paginationQuery, [
                'max_buttons' => 7,
                'link_class' => 'page-link',
                'prev_label' => '<i class="fas fa-chevron-left"></i> ' . htmlspecialchars(__('pagination_previous')),
                'next_label' => htmlspecialchars(__('pagination_next')) . ' <i class="fas fa-chevron-right"></i>',
            ]);
            ?>
        <?php endif; ?>
    </div>

    <?php
    echo renderMapModal([
        'id' => 'subjectMapModal',
        'title_id' => 'subjectMapModalTitle',
        'title_text' => __('maps_add_subject'),
        'icon_class' => 'fas fa-tag',
        'form_id' => 'subjectMapForm',
        'list_type_id' => 'subjectMapListType',
        'entry_type' => 'subject',
        'return_url' => $returnUrl,
        'label_text' => __('msg_subject'),
        'value_id' => 'subjectMapValue',
        'placeholder_text' => __('maps_subject_placeholder'),
        'hint_text' => __('maps_subject_hint')
    ]);

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

    $detailHeaderActions = '
        <form method="POST" action="operations.php" class="modal-action-form">
            <input type="hidden" name="message_ids" id="detailActionSpamId" value="">
            <input type="hidden" name="operation" value="learn_spam">
            <input type="hidden" name="return_url" value="index.php">
            <button type="submit" class="action-btn learn-spam-btn" title="' . safe_html(__('msg_learn_spam')) . '">
                <i class="fas fa-ban"></i>
            </button>
        </form>
        <form method="POST" action="operations.php" class="modal-action-form">
            <input type="hidden" name="message_ids" id="detailActionHamId" value="">
            <input type="hidden" name="operation" value="learn_ham">
            <input type="hidden" name="return_url" value="index.php">
            <button type="submit" class="action-btn learn-ham-btn" title="' . safe_html(__('msg_learn_ham')) . '">
                <i class="fas fa-check"></i>
            </button>
        </form>
        <form method="POST" action="operations.php" class="modal-action-form" data-action="release">
            <input type="hidden" name="message_ids" id="detailActionReleaseId" value="">
            <input type="hidden" name="operation" value="release">
            <input type="hidden" name="return_url" value="index.php">
            <button type="submit" class="action-btn release-btn modal-release-btn" title="' . safe_html(__('msg_release')) . '">
                <i class="fas fa-paper-plane"></i>
            </button>
        </form>
        <form method="POST" action="operations.php" class="modal-action-form" onsubmit="return confirm(\'' . safe_html(__('confirm_delete_message')) . '\');">
            <input type="hidden" name="message_ids" id="detailActionDeleteId" value="">
            <input type="hidden" name="operation" value="delete">
            <input type="hidden" name="return_url" value="index.php">
            <button type="submit" class="action-btn delete-btn" title="' . safe_html(__('msg_delete')) . '">
                <i class="fas fa-trash"></i>
            </button>
        </form>
    ';

    echo renderPreviewModal([
        'id' => 'messageDetailModal',
        'classes' => 'preview-modal message-detail-modal',
        'title_id' => 'detailModalTitle',
        'title_text' => __('view_title'),
        'icon_class' => 'fas fa-envelope-open-text',
        'content_id' => 'detailModalContent',
        'content_class' => 'detail-modal-content',
        'loading_class' => 'detail-loading',
        'loading_text' => __('preview_loading'),
        'header_actions' => $detailHeaderActions
    ]);
    ?>

    <script>
    const senderModal = document.getElementById('senderMapModal');
    const senderModalTitle = document.getElementById('senderMapModalTitle');
    const senderModalValue = document.getElementById('senderMapValue');
    const senderModalListType = document.getElementById('senderMapListType');
    const senderStrings = {
        whitelist: "<?php echo htmlspecialchars(__('maps_add_whitelist_sender')); ?>",
        blacklist: "<?php echo htmlspecialchars(__('maps_add_blacklist_sender')); ?>"
    };

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

    function openSenderModal(listType, sender) {
        senderModalListType.value = listType;
        senderModalTitle.innerHTML = `<i class="fas fa-paper-plane"></i> ${senderStrings[listType]}`;
        senderModalValue.value = sender.trim();
        senderModal.classList.add('active');
        senderModal.setAttribute('aria-hidden', 'false');
        senderModalValue.focus();
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

    function closeSenderModal() {
        senderModal.classList.remove('active');
        senderModal.setAttribute('aria-hidden', 'true');
    }

    document.querySelectorAll('.sender-map-btn').forEach((button) => {
        button.addEventListener('click', () => {
            openSenderModal(button.dataset.listType, button.dataset.sender || '');
        });
    });

    document.querySelectorAll('.subject-map-btn').forEach((button) => {
        button.addEventListener('click', () => {
            openSubjectModal(button.dataset.listType, button.dataset.subject || '');
        });
    });

    senderModal.querySelectorAll('.modal-close, .modal-dismiss').forEach((button) => {
        button.addEventListener('click', closeSenderModal);
    });

    subjectModal.querySelectorAll('.modal-close, .modal-dismiss').forEach((button) => {
        button.addEventListener('click', closeSubjectModal);
    });

    senderModal.addEventListener('click', (event) => {
        if (event.target === senderModal) {
            closeSenderModal();
        }
    });

    subjectModal.addEventListener('click', (event) => {
        if (event.target === subjectModal) {
            closeSubjectModal();
        }
    });

    // Detail modal functionality
    let activeRequest = null;
    const detailModal = document.getElementById('messageDetailModal');
    const detailModalContent = document.getElementById('detailModalContent');
    const isAdmin = <?php echo json_encode($isAdmin); ?>;
    const releaseActionButton = detailModal.querySelector('.modal-release-btn');
    const actionIdFields = [
        document.getElementById('detailActionSpamId'),
        document.getElementById('detailActionHamId'),
        document.getElementById('detailActionReleaseId'),
        document.getElementById('detailActionDeleteId')
    ].filter(Boolean);

    const detailStrings = {
        loading: "<?php echo htmlspecialchars(__('preview_loading')); ?>",
        previewTitle: "<?php echo htmlspecialchars(__('preview_message_title')); ?>",
        previewModeHtml: "<?php echo htmlspecialchars(__('preview_mode_html')); ?>",
        previewModeText: "<?php echo htmlspecialchars(__('preview_mode_text')); ?>",
        previewError: "<?php echo htmlspecialchars(__('preview_error')); ?>",
        previewParseError: "<?php echo htmlspecialchars(__('preview_parse_error')); ?>",
        previewLoadFailed: "<?php echo htmlspecialchars(__('preview_load_failed')); ?>",
        previewNetworkError: "<?php echo htmlspecialchars(__('preview_network_error')); ?>",
        infoTitle: "<?php echo htmlspecialchars(__('view_basic_info')); ?>",
        subject: "<?php echo htmlspecialchars(__('msg_subject')); ?>",
        sender: "<?php echo htmlspecialchars(__('msg_sender')); ?>",
        recipient: "<?php echo htmlspecialchars(__('msg_recipient')); ?>",
        fromHeader: "<?php echo htmlspecialchars(__('view_from_header')); ?>",
        toHeader: "<?php echo htmlspecialchars(__('view_to_header')); ?>",
        dkimDmarc: "<?php echo htmlspecialchars(__('view_dkim_dmarc')); ?>",
        dkimLabel: "<?php echo htmlspecialchars(__('view_dkim_label')); ?>",
        dmarcLabel: "<?php echo htmlspecialchars(__('view_dmarc_label')); ?>",
        spamHeader: "<?php echo htmlspecialchars(__('view_spam_header')); ?>",
        userAgent: "<?php echo htmlspecialchars(__('view_user_agent')); ?>",
        ipAddress: "<?php echo htmlspecialchars(__('ip_address')); ?>",
        authUser: "<?php echo htmlspecialchars(__('view_authenticated_user')); ?>",
        action: "<?php echo htmlspecialchars(__('msg_action')); ?>",
        score: "<?php echo htmlspecialchars(__('msg_score')); ?>",
        status: "<?php echo htmlspecialchars(__('status')); ?>",
        yes: "<?php echo htmlspecialchars(__('yes')); ?>",
        no: "<?php echo htmlspecialchars(__('no')); ?>",
        stateQuarantined: "<?php echo htmlspecialchars(__('state_quarantined')); ?>",
        stateLearnedHam: "<?php echo htmlspecialchars(__('state_learned_ham')); ?>",
        stateLearnedSpam: "<?php echo htmlspecialchars(__('state_learned_spam')); ?>",
        stateReleased: "<?php echo htmlspecialchars(__('state_released')); ?>",
        actionReject: "<?php echo htmlspecialchars(__('action_reject')); ?>",
        actionNoAction: "<?php echo htmlspecialchars(__('action_no_action')); ?>",
        actionAddHeader: "<?php echo htmlspecialchars(__('action_add_header')); ?>",
        actionGreylist: "<?php echo htmlspecialchars(__('action_greylist')); ?>",
        actionSoftReject: "<?php echo htmlspecialchars(__('action_soft_reject')); ?>"
    };

    document.addEventListener('DOMContentLoaded', function() {
        document.querySelectorAll('.subject-preview-btn').forEach((button) => {
            button.addEventListener('click', () => {
                openDetailModal(button.dataset.messageId);
            });
        });

        detailModal.querySelectorAll('.modal-close').forEach((button) => {
            button.addEventListener('click', closeDetailModal);
        });

        detailModal.addEventListener('click', (event) => {
            if (event.target === detailModal) {
                closeDetailModal();
            }
        });

        document.addEventListener('keydown', (event) => {
            if (event.key === 'Escape' && detailModal.classList.contains('active')) {
                closeDetailModal();
            }
        });
    });

    function openDetailModal(msgId) {
        if (!msgId) {
            return;
        }

        actionIdFields.forEach((field) => {
            field.value = msgId;
        });

        if (activeRequest) {
            activeRequest.abort();
        }

        detailModalContent.innerHTML = `<div class="detail-loading"><i class="fas fa-spinner fa-spin"></i> ${detailStrings.loading}</div>`;
        detailModal.classList.add('active');
        detailModal.setAttribute('aria-hidden', 'false');

        activeRequest = new XMLHttpRequest();
        activeRequest.open('GET', 'api_message_preview.php?id=' + encodeURIComponent(msgId) + '&format=auto', true);

        activeRequest.onload = function() {
            if (activeRequest.status === 200) {
                try {
                    const data = JSON.parse(activeRequest.responseText);

                    if (data.success) {
                        renderDetailModal(data);
                    } else {
                        detailModalContent.innerHTML = `<div class="preview-error">${detailStrings.previewError}: ${escapeHtml(data.error)}</div>`;
                    }
                } catch (e) {
                    detailModalContent.innerHTML = `<div class="preview-error">${detailStrings.previewParseError}</div>`;
                }
            } else {
                detailModalContent.innerHTML = `<div class="preview-error">${detailStrings.previewLoadFailed}</div>`;
            }
            activeRequest = null;
        };

        activeRequest.onerror = function() {
            detailModalContent.innerHTML = `<div class="preview-error">${detailStrings.previewNetworkError}</div>`;
            activeRequest = null;
        };

        activeRequest.send();
    }

    function renderDetailModal(data) {
        const senderValue = data.sender_decoded || data.sender || '';
        const subjectValue = data.subject_decoded || data.subject || '';

        const formatIndicator = data.is_html
            ? `<span class="preview-format-indicator"><i class="fas fa-code"></i> ${detailStrings.previewModeHtml}</span>`
            : (data.has_html ? `<span class="preview-format-indicator muted"><i class="fas fa-align-left"></i> ${detailStrings.previewModeText}</span>` : '');

        const previewHeader = `
            <div class="detail-preview-header">
                <h4><i class="fas fa-envelope"></i> ${detailStrings.previewTitle} ${formatIndicator}</h4>
                <div class="preview-meta"><strong>${detailStrings.sender}:</strong> ${escapeHtml(senderValue)}</div>
                <div class="preview-meta"><strong>${detailStrings.subject}:</strong> ${escapeHtml(subjectValue)}</div>
                <div class="preview-meta"><strong><?php echo htmlspecialchars(__('time')); ?>:</strong> ${escapeHtml(data.timestamp)} | <strong>${detailStrings.score}:</strong> ${escapeHtml(String(data.score))}</div>
            </div>
        `;

        const previewBody = data.is_html
            ? `<div class="detail-preview-body"><iframe class="preview-iframe" sandbox="" referrerpolicy="no-referrer"></iframe></div>`
            : `<div class="detail-preview-body"><pre>${escapeHtml(data.preview)}</pre></div>`;

        detailModalContent.innerHTML = `
            <div class="detail-modal-grid">
                <div class="detail-preview-panel">
                    ${previewHeader}
                    ${previewBody}
                </div>
            </div>
        `;

        if (data.is_html) {
            const iframe = detailModalContent.querySelector('.preview-iframe');
            iframe.srcdoc = data.preview;
        }

        if (!isAdmin && releaseActionButton) {
            const releaseBlocked = Boolean(data.has_virus_symbol || data.has_bad_attachment_symbol);
            releaseActionButton.disabled = releaseBlocked;
        } else if (releaseActionButton) {
            releaseActionButton.disabled = false;
        }
    }

    function buildActionBadge(action) {
        const actionKey = (action || '').toLowerCase();
        const actionMap = {
            'reject': { label: detailStrings.actionReject, className: 'badge badge-reject', icon: 'fa-ban' },
            'no action': { label: detailStrings.actionNoAction, className: 'badge badge-pass', icon: 'fa-check-circle' },
            'pass': { label: detailStrings.actionNoAction, className: 'badge badge-pass', icon: 'fa-check-circle' },
            'add header': { label: detailStrings.actionAddHeader, className: 'badge badge-header', icon: 'fa-tag' },
            'greylist': { label: detailStrings.actionGreylist, className: 'badge badge-pass', icon: 'fa-clock' },
            'soft reject': { label: detailStrings.actionSoftReject, className: 'badge badge-soft-reject', icon: 'fa-exclamation-triangle' },
            'soft_reject': { label: detailStrings.actionSoftReject, className: 'badge badge-soft-reject', icon: 'fa-exclamation-triangle' }
        };

        const actionData = actionMap[actionKey] || { label: action || '-', className: 'badge badge-pass', icon: 'fa-question-circle' };
        return `<span class="${actionData.className}"><i class="fas ${actionData.icon}"></i> ${escapeHtml(actionData.label)}</span>`;
    }

    function getStateLabel(state, stateBy, stateAt) {
        let label = detailStrings.stateQuarantined;
        switch (parseInt(state, 10)) {
            case 1:
                label = detailStrings.stateLearnedHam;
                break;
            case 2:
                label = detailStrings.stateLearnedSpam;
                break;
            case 3:
                label = detailStrings.stateReleased;
                break;
            default:
                label = detailStrings.stateQuarantined;
        }
        const parts = [label];
        if (stateBy) {
            parts.push(escapeHtml(stateBy));
        }
        if (stateAt) {
            parts.push(escapeHtml(stateAt));
        }
        return parts.join(' · ');
    }

    function closeDetailModal() {
        detailModal.classList.remove('active');
        detailModal.setAttribute('aria-hidden', 'true');

        if (activeRequest) {
            activeRequest.abort();
            activeRequest = null;
        }
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text ?? '';
        return div.innerHTML;
    }
    </script>
    <?php include 'footer.php'; ?>
</body>
</html>
