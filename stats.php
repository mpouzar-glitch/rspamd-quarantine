<?php
// stats.php - Statistiky a grafy pro Rspamd Quarantine
// Zobrazuje detailní statistiky s grafy a tabulkami
// Podporuje multidomain filtraci pro domain_admin uživatele

session_start();
require_once 'config.php';
require_once 'functions.php';
require_once 'filter_helper.php';

// Check authentication
if (!isAuthenticated()) {
    header('Location: login.php');
    exit;
}

$db = Database::getInstance()->getConnection();
$userRole = $_SESSION['user_role'] ?? 'viewer';
$user = $_SESSION['username'] ?? 'unknown';

// Time range for stats (default: last 30 days)
$days = isset($_GET['days']) ? max(1, min(365, (int)$_GET['days'])) : 30;
$dateFrom = date('Y-m-d 00:00:00', strtotime("-$days days"));
$dateTo = date('Y-m-d 23:59:59');

// Get domain filter SQL
$params = [];
$domainFilter = getDomainFilterSQL($params);

// Get all statistics
$topRecipients = getTopRecipients($db, $dateFrom, $dateTo, $domainFilter, $params, 40);
$topSenders = getTopSenders($db, $dateFrom, $dateTo, $domainFilter, $params, 40);
$volumeStats = getVolumeStats($db, $dateFrom, $dateTo, $domainFilter, $params);
$actionDist = getActionDistribution($db, $dateFrom, $dateTo, $domainFilter, $params);
$stateDist = getStateDistribution($db, $dateFrom, $dateTo, $domainFilter, $params);
$dailyTrace = getDailyTrace($db, $dateFrom, $dateTo, $domainFilter, $params);
$weeklyTrace = getWeeklyTrace($db, $dateFrom, $dateTo, $domainFilter, $params);

$pageTitle = 'Statistiky - Rspamd Quarantine';

// Funkce pro zkrácení textu s tooltipem
function truncateWithTooltip($text, $maxLength = 40) {
    $text = htmlspecialchars($text);
    if (mb_strlen($text) > $maxLength) {
        $truncated = mb_substr($text, 0, $maxLength) . '...';
        return '<span title="' . $text . '" style="cursor: help; text-decoration: underline dotted;">' . $truncated . '</span>';
    }
    return $text;
}

include 'menu.php';
?>
<!DOCTYPE html>
<html lang="cs">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($pageTitle); ?></title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/all.min.css">
    <link rel="stylesheet" href="css/style.css">
    <link rel="stylesheet" href="css/stats-inline.css">
    <link rel="stylesheet" href="css/stats.css">
</head>
<body>

<div class="stats-container">
    <div class="header-with-stats">
        <div class="header-title">
            <h1><i class="fas fa-chart-bar"></i> Statistiky a grafy</h1>
        </div>
        <div class="stats-inline">
            <div class="stat-inline-item total">
                <i class="fas fa-inbox"></i>
                <div>
                    <span class="stat-inline-label">Karanténa</span>
                    <span class="stat-inline-value"><?php echo number_format($volumeStats['quarantine']['total_messages'] ?? 0); ?></span>
                </div>
            </div>

            <div class="stat-inline-item" style="border-left-color: #3498db;">
                <i class="fas fa-database"></i>
                <div>
                    <span class="stat-inline-label">Objem dat</span>
                    <span class="stat-inline-value"><?php echo formatMessageSize($volumeStats['quarantine']['total_bytes'] ?? 0); ?></span>
                </div>
            </div>

            <div class="stat-inline-item" style="border-left-color: #2ecc71;">
                <i class="fas fa-route"></i>
                <div>
                    <span class="stat-inline-label">Trace celkem</span>
                    <span class="stat-inline-value"><?php echo number_format($volumeStats['trace']['total_messages'] ?? 0); ?></span>
                </div>
            </div>

            <div class="stat-inline-item score">
                <i class="fas fa-chart-line"></i>
                <div>
                    <span class="stat-inline-label">Ø Skóre</span>
                    <span class="stat-inline-value"><?php echo number_format($volumeStats['quarantine']['avg_score'] ?? 0, 2); ?></span>
                </div>
            </div>
        </div>
    </div>    
 
    <div style="margin-bottom: 20px; color: #7f8c8d; font-size: 14px;">
        <i class="far fa-calendar-alt"></i> Období: <?php echo date('d.m.Y', strtotime($dateFrom)); ?> - <?php echo date('d.m.Y', strtotime($dateTo)); ?>
        <?php if ($userRole !== 'admin'): ?>
        &nbsp;&nbsp;<i class="fas fa-filter"></i> Filtrováno pro domény: <?php echo htmlspecialchars(implode(', ', $_SESSION['user_domains'] ?? [])); ?>
        <?php endif; ?>
    </div>

    <!-- Time Selector -->
    <div class="time-selector">
        <label><i class="fas fa-calendar-alt"></i> Časové období:</label>
        <a href="?days=7" class="<?php echo $days == 7 ? 'active' : ''; ?>">7 dní</a>
        <a href="?days=14" class="<?php echo $days == 14 ? 'active' : ''; ?>">14 dní</a>
        <a href="?days=30" class="<?php echo $days == 30 ? 'active' : ''; ?>">30 dní</a>
        <a href="?days=60" class="<?php echo $days == 60 ? 'active' : ''; ?>">60 dní</a>
        <a href="?days=90" class="<?php echo $days == 90 ? 'active' : ''; ?>">90 dní</a>
    </div>

    <div class="charts-grid">
    <!-- Action Distribution Chart -->
    <div class="chart-container">
        <h2><i class="fas fa-pie-chart"></i> Rozložení podle akcí (Message Trace)</h2>
        <div class="chart-wrapper">
            <canvas id="actionChart"></canvas>
        </div>
    </div>

    <!-- State Distribution Chart -->
    <div class="chart-container">
        <h2><i class="fas fa-chart-pie"></i> Rozložení podle stavu (Karanténa)</h2>
        <div class="chart-wrapper">
            <canvas id="stateChart"></canvas>
        </div>
    </div>

    <!-- Daily Trace Chart -->
    <div class="chart-container">
        <h2><i class="fas fa-chart-area"></i> Denní graf zpráv (Message Trace)</h2>
        <div class="chart-wrapper chart-wrapper-large">
            <canvas id="dailyChart"></canvas>
        </div>
    </div>

    <!-- Weekly Trace Chart -->
    <div class="chart-container">
        <h2><i class="fas fa-chart-bar"></i> Týdenní graf zpráv (Message Trace)</h2>
        <div class="chart-wrapper chart-wrapper-large">
            <canvas id="weeklyChart"></canvas>
        </div>
    </div>

    </div>

    <div class="tables-grid">
    <!-- Top Recipients Table -->
    <div class="table-container">
        <h2><i class="fas fa-users"></i> Top příjemci</h2>
        <table class="messages-table">
            <thead>
                <tr>
                    <th style="width: 40px;">#</th>
                    <th style="width: 300px;">Příjemce</th>
                    <th style="width: 100px;">Počet</th>
                    <th style="width: 100px;">Průměrné skóre</th>
                    <th>Max skóre</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($topRecipients as $i => $recipient): ?>
                <?php if($i>40) break; ?>
                <tr>
                    <td><?php echo $i + 1; ?></td>
                    <td><strong><?php echo truncateWithTooltip($recipient['recipients'], 40); ?></strong></td>
                    <td><?php echo number_format($recipient['count']); ?></td>
                    <td>
                        <?php 
                        $score = $recipient['avg_score'];
                        $scoreClass = $score >= 15 ? 'badge-high' : ($score >= 6 ? 'badge-medium' : 'badge-low');
                        ?>
                        <span class="badge <?php echo $scoreClass; ?>"><?php echo number_format($score, 2); ?></span>
                    </td>
                    <td>
                        <?php 
                        $score = $recipient['max_score'];
                        $scoreClass = $score >= 15 ? 'badge-high' : ($score >= 6 ? 'badge-medium' : 'badge-low');
                        ?>
                        <span class="badge <?php echo $scoreClass; ?>"><?php echo number_format($score, 2); ?></span>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>

    <!-- Top Senders Table -->
    <div class="table-container">
        <h2><i class="fas fa-paper-plane"></i> Top odesílatelé</h2>
        <table class="messages-table">
            <thead>
                <tr>
                    <th style="width: 40px;">#</th>
                    <th style="width: 300px;">Odesílatel</th>
                    <th style="width: 100px;">Počet</th>
                    <th style="width: 100px;">Průměrné skóre</th>
                    <th>Max skóre</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($topSenders as $i => $sender): ?>
                <?php if($i>40) break; ?>
                <tr>
                    <td><?php echo $i + 1; ?></td>
                    <td><strong><?php echo truncateWithTooltip($sender['sender'], 40); ?></strong></td>
                    <td><?php echo number_format($sender['count']); ?></td>
                    <td>
                        <?php 
                        $score = $sender['avg_score'] ?? 0;
                        $scoreClass = $score >= 15 ? 'badge-high' : ($score >= 6 ? 'badge-medium' : 'badge-low');
                        ?>
                        <span class="badge <?php echo $scoreClass; ?>"><?php echo number_format($score, 2); ?></span>
                    </td>
                    <td>
                        <?php 
                        $score = $sender['max_score'] ?? 0;
                        $scoreClass = $score >= 15 ? 'badge-high' : ($score >= 6 ? 'badge-medium' : 'badge-low');
                        ?>
                        <span class="badge <?php echo $scoreClass; ?>"><?php echo number_format($score, 2); ?></span>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
  </div>
</div>

<script>
// Action Distribution Chart (Pie)
<?php
$actionLabels = [];
$actionData = [];
$actionColors = [
    'reject' => '#e74c3c',
    'add header' => '#f39c12',
    'pass' => '#28a745',
    'soft reject' => '#17a2b8',
    'no action' => '#27ae60',
    'greylist' => '#007bff'
];
foreach ($actionDist as $item) {
    $actionLabels[] = $item['action'];
    $actionData[] = $item['count'];
}
?>
new Chart(document.getElementById('actionChart'), {
    type: 'pie',
    data: {
        labels: <?php echo json_encode($actionLabels); ?>,
        datasets: [{
            data: <?php echo json_encode($actionData); ?>,
            backgroundColor: <?php echo json_encode(array_map(function($label) use ($actionColors) {
                return $actionColors[strtolower($label)] ?? '#6c757d';
            }, $actionLabels)); ?>
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                position: 'right'
            },
            tooltip: {
                callbacks: {
                    label: function(context) {
                        return context.label + ': ' + context.parsed.toLocaleString() + ' zpráv';
                    }
                }
            }
        }
    }
});

// State Distribution Chart (Doughnut)
<?php
$stateLabels = [];
$stateData = [];
// State colors inline
foreach ($stateDist as $item) {
    $stateLabels[] = $item['state_name'];
    $stateData[] = $item['count'];
}
?>
new Chart(document.getElementById('stateChart'), {
    type: 'doughnut',
    data: {
        labels: <?php echo json_encode($stateLabels); ?>,
        datasets: [{
            data: <?php echo json_encode($stateData); ?>,
            backgroundColor: <?php echo json_encode(array_map(function($label) {
                        $cm = ['quarantined'=>'#95a5a6','karanténa'=>'#95a5a6','spam'=>'#e74c3c','learned_spam'=>'#e74c3c','ham'=>'#27ae60','learned_ham'=>'#27ae60','released'=>'#17a2b8','uvolněno'=>'#17a2b8'];
                        return $cm[strtolower(trim($label))]??'#6c757d';
                    }, $stateLabels)); ?>
        }]
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                position: 'right'
            },
            tooltip: {
                callbacks: {
                    label: function(context) {
                        return context.label + ': ' + context.parsed.toLocaleString() + ' zpráv';
                    }
                }
            }
        }
    }
});

// Daily Trace Chart (Area/Line)
<?php
$dailyDates = [];
$dailyActions = [];
foreach ($dailyTrace as $row) {
    if (!in_array($row['date'], $dailyDates)) {
        $dailyDates[] = $row['date'];
    }
    if (!isset($dailyActions[$row['action']])) {
        $dailyActions[$row['action']] = [];
    }
    $dailyActions[$row['action']][$row['date']] = $row['count'];
}

$dailyDatasets = [];
foreach ($dailyActions as $action => $data) {
    $dataPoints = [];
    foreach ($dailyDates as $date) {
        $dataPoints[] = $data[$date] ?? 0;
    }
    $dailyDatasets[] = [
        'label' => $action,
        'data' => $dataPoints,
        'backgroundColor' => $actionColors[strtolower($action)] ?? '#6c757d',
        'borderColor' => $actionColors[strtolower($action)] ?? '#6c757d',
        'fill' => true,
        'tension' => 0.4
    ];
}
?>
new Chart(document.getElementById('dailyChart'), {
    type: 'line',
    data: {
        labels: <?php echo json_encode(array_map(function($d) { return date('d.m.', strtotime($d)); }, $dailyDates)); ?>,
        datasets: <?php echo json_encode($dailyDatasets); ?>
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
            y: {
                beginAtZero: true,
                stacked: true
            },
            x: {
                stacked: true
            }
        },
        plugins: {
            legend: {
                position: 'top'
            },
            tooltip: {
                mode: 'index',
                intersect: false
            }
        }
    }
});

// Weekly Trace Chart (Bar)
<?php
$weeklyDates = [];
$weeklyActions = [];
foreach ($weeklyTrace as $row) {
    $weekLabel = date('W/Y', strtotime($row['week_start']));
    if (!in_array($weekLabel, $weeklyDates)) {
        $weeklyDates[] = $weekLabel;
    }
    if (!isset($weeklyActions[$row['action']])) {
        $weeklyActions[$row['action']] = [];
    }
    $weeklyActions[$row['action']][$weekLabel] = $row['count'];
}

$weeklyDatasets = [];
foreach ($weeklyActions as $action => $data) {
    $dataPoints = [];
    foreach ($weeklyDates as $week) {
        $dataPoints[] = $data[$week] ?? 0;
    }
    $weeklyDatasets[] = [
        'label' => $action,
        'data' => $dataPoints,
        'backgroundColor' => $actionColors[strtolower($action)] ?? '#6c757d'
    ];
}
?>
new Chart(document.getElementById('weeklyChart'), {
    type: 'bar',
    data: {
        labels: <?php echo json_encode($weeklyDates); ?>,
        datasets: <?php echo json_encode($weeklyDatasets); ?>
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
            y: {
                beginAtZero: true,
                stacked: true
            },
            x: {
                stacked: true
            }
        },
        plugins: {
            legend: {
                position: 'top'
            },
            tooltip: {
                mode: 'index',
                intersect: false
            }
        }
    }
});
</script>
<?php include 'footer.php'; ?>
</body>
</html>
