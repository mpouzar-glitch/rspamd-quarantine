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

// Get filters from request
$filters = getTraceFiltersFromRequest();

// Pagination
$page = isset($_GET['page']) ? max(1, (int)$_GET['page']) : 1;
$offset = ($page - 1) * ITEMS_PER_PAGE;

// Get total count
$totalItems = countTraceMessages($db, $filters);
$totalPages = max(1, (int)ceil($totalItems / ITEMS_PER_PAGE));

// Build and execute query
$params = [];
$sql = buildTraceQuery($filters, $params, [
    'limit' => ITEMS_PER_PAGE,
    'offset' => $offset,
]);

$stmt = $db->prepare($sql);
$stmt->execute($params);
$messages = $stmt->fetchAll(PDO::FETCH_ASSOC);

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
    <link rel="stylesheet" href="css/trace.css">
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
            'show_ip' => ($filters['ip']),
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
                            <th class="col-timestamp"><?php echo htmlspecialchars(__('time')); ?></th>
                            <th class="col-email"><?php echo htmlspecialchars(__('msg_sender')); ?></th>
                            <th class="col-email"><?php echo htmlspecialchars(__('msg_recipient')); ?></th>
                            <th class="col-subject"><?php echo htmlspecialchars(__('msg_subject')); ?></th>
                            <th class="col-action"><?php echo htmlspecialchars(__('action')); ?></th>
                            <th class="col-score"><?php echo htmlspecialchars(__('msg_score')); ?></th>
                            <th class="col-ip"><?php echo htmlspecialchars(__('ip_address')); ?></th>
                            <th class="col-hostname"><?php echo htmlspecialchars(__('hostname')); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($messages as $msg): ?>
                            <?php
                            $msgId = $msg['id'];
                            $sender = decodeMimeHeader($msg['sender']);
                            $recipients = decodeMimeHeader($msg['recipients']);
                            $subject = decodeMimeHeader($msg['subject']) ?: __('msg_no_subject');
                            $score = round($msg['score'], 2);
                            $timestamp = date('d.m. H:i', strtotime($msg['timestamp']));
                            $action = $msg['action'] ?? 'unknown';
                            $ipAddress = $msg['ip_address'] ?? '-';
                            $hostname = $msg['hostname'] ?? '-';
                            $symbols = $msg['symbols'] ?? '';

                            // Parse symbols like in view.php
                            $parsed_symbols = [];
                            if (!empty($symbols)) {
                                // Try JSON format first (Rspamd format)
                                if (preg_match_all('/"name":"([^"]+)".*?"score":([+-]?\d+(?:\.\d+)?)/s', $symbols, $matches, PREG_SET_ORDER)) {
                                    foreach ($matches as $match) {
                                        $name = trim($match[1]);
                                        $sym_score = floatval($match[2]);
                                        if ($name) {
                                            $parsed_symbols[] = ['name' => $name, 'score' => $sym_score];
                                        }
                                    }
                                } else {
                                    // Fallback: try simple format "SYMBOL(score)"
                                    $symbol_list = explode(',', $symbols);
                                    foreach ($symbol_list as $symbol_item) {
                                        if (preg_match('/^\s*([^(]+)\(([^)]+)\)\s*$/', $symbol_item, $match)) {
                                            $parsed_symbols[] = [
                                                'name' => trim($match[1]),
                                                'score' => floatval($match[2])
                                            ];
                                        }
                                    }
                                }
                                // Sort by score descending
                                usort($parsed_symbols, function($a, $b) {
                                    return $b['score'] <=> $a['score'];
                                });
                            }

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

                            // Score class
                            if ($score >= 15) {
                                $scoreClass = 'score-high';
                            } elseif ($score >= 6) {
                                $scoreClass = 'score-medium';
                            } else {
                                $scoreClass = 'score-low';
                            }
                            ?>
                            <tr>
                                <td class="timestamp"><?php echo htmlspecialchars($timestamp); ?></td>
                                <td class="email-field">
                                    <i class="fas fa-paper-plane"></i> 
                                    <a href="?sender=<?php echo urlencode($sender); ?>" 
                                       class="email-link" 
                                       title="<?php echo htmlspecialchars(__('filter_by_sender', ['sender' => $sender])); ?>">
                                        <?php echo htmlspecialchars(truncateText($sender, 40)); ?>
                                    </a>
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
                                    <?php echo htmlspecialchars(truncateText($subject, 50)); ?>
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

                                        <!-- Symbols popup on hover -->
                                        <?php if (!empty($parsed_symbols)): ?>
                                            <div class="symbols-popup">
                                                <div class="symbols-popup-header">
                                                    <i class="fas fa-list-ul"></i> <?php echo htmlspecialchars(__('symbols_header', ['count' => count($parsed_symbols)])); ?>
                                                </div>
                                                <div class="symbols-grid">
                                                    <?php foreach ($parsed_symbols as $sym): 
                                                        $sym_score = $sym['score'];
                                                        // Same color logic as view.php
                                                        $bg_color = $sym_score > 1 ? '#e74c3c' : ($sym_score > 0 ? '#f39c12' : ($sym_score < 0 ? '#27ae60' : '#95a5a6'));
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

    <script>
        function toggleFilters() {
            const content = document.getElementById('filterContent');
            const icon = document.querySelector('.toggle-icon');
            content.classList.toggle('active');
            icon.classList.toggle('rotated');
        }
    </script>
</body>
</html>
