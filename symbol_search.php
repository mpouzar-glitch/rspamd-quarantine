<?php
/*
 * Version: 2.0.0
 * Author: Martin Pouzar
 * License: GNU General Public License v3.0
 */
// symbol_search.php - Symbol search and statistics

session_start();
require_once 'config.php';
require_once 'functions.php';
require_once 'filter_helper.php';
require_once 'lang_helper.php';

// Check authentication
if (!isAuthenticated()) {
    header('Location: login.php');
    exit;
}

$db = Database::getInstance()->getConnection();
$userRole = $_SESSION['user_role'] ?? 'viewer';

$days = isset($_GET['days']) ? max(1, min(365, (int)$_GET['days'])) : 30;
$dateFrom = date('Y-m-d 00:00:00', strtotime("-$days days"));
$dateTo = date('Y-m-d 23:59:59');

$params = [];
$domainFilter = getDomainFilterSQL($params);

$searchTerm = trim($_GET['search'] ?? '');
$selectedSymbol = trim($_GET['symbol'] ?? '');

$symbolStats = [];
if ($searchTerm !== '') {
    $symbolStats = searchSymbolsWithStats($db, $searchTerm, $dateFrom, $dateTo, $domainFilter, $params, 100);
}

$symbolMessages = [];
if ($selectedSymbol !== '') {
    $symbolMessages = getSymbolMessages($db, $selectedSymbol, $dateFrom, $dateTo, $domainFilter, $params, 200);
}

$symbolCount = count($symbolStats);
$messageCount = count($symbolMessages);

$page_title = __('symbol_search_page_title', ['app' => __('app_title')]);
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
    <link rel="stylesheet" href="css/stats.css">
</head>
<body>
    <div class="stats-container">
        <div class="header-with-stats">
            <div class="header-title">
                <h1><i class="fas fa-magnifying-glass-chart"></i> <?php echo htmlspecialchars(__('symbol_search_title')); ?></h1>
            </div>
            <div class="stats-inline">
                <div class="stat-inline-item total">
                    <i class="fas fa-tags"></i>
                    <div>
                        <span class="stat-inline-label"><?php echo htmlspecialchars(__('symbol_search_symbols_count')); ?></span>
                        <span class="stat-inline-value"><?php echo number_format($symbolCount); ?></span>
                    </div>
                </div>
                <div class="stat-inline-item" style="border-left-color: #2ecc71;">
                    <i class="fas fa-envelope"></i>
                    <div>
                        <span class="stat-inline-label"><?php echo htmlspecialchars(__('symbol_search_messages_count')); ?></span>
                        <span class="stat-inline-value"><?php echo number_format($messageCount); ?></span>
                    </div>
                </div>
            </div>
        </div>

        <div style="margin-bottom: 20px; color: #7f8c8d; font-size: 14px;">
            <i class="far fa-calendar-alt"></i> <?php echo __(
                'stats_period',
                [
                    'from' => date('d.m.Y', strtotime($dateFrom)),
                    'to' => date('d.m.Y', strtotime($dateTo)),
                ]
            ); ?>
            <?php if ($userRole !== 'admin'): ?>
            &nbsp;&nbsp;<i class="fas fa-filter"></i> <?php echo __(
                'stats_filtered_domains',
                [
                    'domains' => htmlspecialchars(implode(', ', $_SESSION['user_domains'] ?? [])),
                ]
            ); ?>
            <?php endif; ?>
        </div>

        <div class="stats-subnav">
            <a href="stats.php">
                <i class="fas fa-chart-bar"></i> <?php echo htmlspecialchars(__('stats_subnav_overview')); ?>
            </a>
            <a href="symbol_search.php" class="active">
                <i class="fas fa-magnifying-glass-chart"></i> <?php echo htmlspecialchars(__('stats_subnav_symbol_search')); ?>
            </a>
        </div>

        <div class="time-selector">
            <label><i class="fas fa-calendar-alt"></i> <?php echo htmlspecialchars(__('stats_time_range_label')); ?></label>
            <?php
            $buildDaysLink = function (int $range) use ($searchTerm, $selectedSymbol) {
                $params = ['days' => $range];
                if ($searchTerm !== '') {
                    $params['search'] = $searchTerm;
                }
                if ($selectedSymbol !== '') {
                    $params['symbol'] = $selectedSymbol;
                }
                return '?' . http_build_query($params);
            };
            ?>
            <a href="<?php echo $buildDaysLink(7); ?>" class="<?php echo $days == 7 ? 'active' : ''; ?>"><?php echo htmlspecialchars(__('stats_days', ['days' => 7])); ?></a>
            <a href="<?php echo $buildDaysLink(14); ?>" class="<?php echo $days == 14 ? 'active' : ''; ?>"><?php echo htmlspecialchars(__('stats_days', ['days' => 14])); ?></a>
            <a href="<?php echo $buildDaysLink(30); ?>" class="<?php echo $days == 30 ? 'active' : ''; ?>"><?php echo htmlspecialchars(__('stats_days', ['days' => 30])); ?></a>
            <a href="<?php echo $buildDaysLink(60); ?>" class="<?php echo $days == 60 ? 'active' : ''; ?>"><?php echo htmlspecialchars(__('stats_days', ['days' => 60])); ?></a>
            <a href="<?php echo $buildDaysLink(90); ?>" class="<?php echo $days == 90 ? 'active' : ''; ?>"><?php echo htmlspecialchars(__('stats_days', ['days' => 90])); ?></a>
        </div>

        <?php displayAlerts(); ?>

        <div class="filters-card">
            <form method="get">
                <input type="hidden" name="days" value="<?php echo (int)$days; ?>">
                <div class="filters-grid">
                    <div class="form-group">
                        <label for="symbolSearch"><?php echo htmlspecialchars(__('symbol_search_input_label')); ?></label>
                        <input id="symbolSearch" class="form-control" type="text" name="search" value="<?php echo htmlspecialchars($searchTerm); ?>" placeholder="<?php echo htmlspecialchars(__('symbol_search_placeholder')); ?>">
                    </div>
                    <div class="form-group">
                        <label for="symbolSelect"><?php echo htmlspecialchars(__('symbol_search_symbol_label')); ?></label>
                        <input id="symbolSelect" class="form-control" type="text" name="symbol" value="<?php echo htmlspecialchars($selectedSymbol); ?>" placeholder="<?php echo htmlspecialchars(__('symbol_search_symbol_placeholder')); ?>">
                    </div>
                </div>
                <div class="filter-actions">
                    <button type="submit" class="btn btn-primary">
                        <i class="fas fa-search"></i> <?php echo htmlspecialchars(__('symbol_search_submit')); ?>
                    </button>
                    <a class="btn btn-secondary" href="symbol_search.php">
                        <i class="fas fa-undo"></i> <?php echo htmlspecialchars(__('reset')); ?>
                    </a>
                </div>
            </form>
        </div>

        <?php if ($searchTerm === ''): ?>
            <div class="empty-state">
                <i class="fas fa-tags"></i>
                <h3><?php echo htmlspecialchars(__('symbol_search_empty_title')); ?></h3>
                <p><?php echo htmlspecialchars(__('symbol_search_empty_desc')); ?></p>
            </div>
        <?php else: ?>
            <div class="table-container">
                <h2><i class="fas fa-tags"></i> <?php echo htmlspecialchars(__('symbol_search_stats_title')); ?></h2>
                <?php if (empty($symbolStats)): ?>
                    <div class="empty-state" style="padding: 30px 10px;">
                        <i class="fas fa-search"></i>
                        <h3><?php echo htmlspecialchars(__('symbol_search_no_results')); ?></h3>
                        <p><?php echo htmlspecialchars(__('symbol_search_no_results_desc')); ?></p>
                    </div>
                <?php else: ?>
                    <table class="messages-table">
                        <thead>
                            <tr>
                                <th style="width: 30%;"><?php echo htmlspecialchars(__('symbol_search_table_symbol')); ?></th>
                                <th style="width: 15%;"><?php echo htmlspecialchars(__('stats_count')); ?></th>
                                <th style="width: 15%;"><?php echo htmlspecialchars(__('stats_avg_score_column')); ?></th>
                                <th style="width: 15%;"><?php echo htmlspecialchars(__('symbol_search_min_score')); ?></th>
                                <th style="width: 15%;"><?php echo htmlspecialchars(__('stats_max_score_column')); ?></th>
                                <th><?php echo htmlspecialchars(__('symbol_search_table_action')); ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($symbolStats as $symbol): ?>
                                <?php
                                $symbolLinkParams = [
                                    'days' => $days,
                                    'search' => $searchTerm,
                                    'symbol' => $symbol['symbol'],
                                ];
                                $symbolLink = 'symbol_search.php?' . http_build_query($symbolLinkParams);
                                ?>
                                <tr>
                                    <td><strong><?php echo htmlspecialchars($symbol['symbol']); ?></strong></td>
                                    <td><?php echo number_format($symbol['count']); ?></td>
                                    <td><?php echo number_format($symbol['avg_score'], 2); ?></td>
                                    <td><?php echo number_format($symbol['min_score'], 2); ?></td>
                                    <td><?php echo number_format($symbol['max_score'], 2); ?></td>
                                    <td>
                                        <a class="btn btn-primary" href="<?php echo htmlspecialchars($symbolLink); ?>">
                                            <i class="fas fa-envelope"></i> <?php echo htmlspecialchars(__('symbol_search_view_messages')); ?>
                                        </a>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            </div>
        <?php endif; ?>

        <div class="table-container">
            <h2><i class="fas fa-envelope"></i> <?php echo htmlspecialchars(__('symbol_search_messages_title')); ?></h2>
            <?php if ($selectedSymbol === ''): ?>
                <div class="empty-state" style="padding: 30px 10px;">
                    <i class="fas fa-mouse-pointer"></i>
                    <h3><?php echo htmlspecialchars(__('symbol_search_messages_empty_title')); ?></h3>
                    <p><?php echo htmlspecialchars(__('symbol_search_messages_empty_desc')); ?></p>
                </div>
            <?php elseif (empty($symbolMessages)): ?>
                <div class="empty-state" style="padding: 30px 10px;">
                    <i class="fas fa-envelope-open"></i>
                    <h3><?php echo htmlspecialchars(__('symbol_search_messages_no_results')); ?></h3>
                    <p><?php echo htmlspecialchars(__('symbol_search_messages_no_results_desc')); ?></p>
                </div>
            <?php else: ?>
                <div style="margin-bottom: 12px; color: #7f8c8d; font-size: 13px;">
                    <strong><?php echo htmlspecialchars($selectedSymbol); ?></strong> · <?php echo __(
                        'symbol_search_messages_count_label',
                        ['count' => number_format($messageCount)]
                    ); ?>
                </div>
                <table class="messages-table">
                    <thead>
                        <tr>
                            <th style="width: 120px;"><?php echo htmlspecialchars(__('time')); ?></th>
                            <th style="width: 180px;"><?php echo htmlspecialchars(__('msg_sender')); ?></th>
                            <th style="width: 180px;"><?php echo htmlspecialchars(__('msg_recipient')); ?></th>
                            <th><?php echo htmlspecialchars(__('msg_subject')); ?></th>
                            <th style="width: 120px;"><?php echo htmlspecialchars(__('action')); ?></th>
                            <th style="width: 90px;"><?php echo htmlspecialchars(__('msg_score')); ?></th>
                            <th style="width: 110px;"><?php echo htmlspecialchars(__('symbol_search_symbol_score')); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($symbolMessages as $message): ?>
                            <tr>
                                <td class="no-wrap"><?php echo htmlspecialchars(date('d.m.Y H:i', strtotime($message['timestamp']))); ?></td>
                                <td><?php echo htmlspecialchars(decodeMimeHeader($message['sender'] ?? '')); ?></td>
                                <td><?php echo htmlspecialchars(decodeMimeHeader($message['recipients'] ?? '')); ?></td>
                                <td><?php echo htmlspecialchars(decodeMimeHeader($message['subject'] ?? '')); ?></td>
                                <td><?php echo htmlspecialchars($message['action'] ?? ''); ?></td>
                                <td><?php echo number_format((float)($message['score'] ?? 0), 2); ?></td>
                                <td><?php echo number_format((float)$message['symbol_score'], 2); ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>
        </div>
    </div>
</body>
</html>
