<?php
/*
 * Version: 2.0.0
 * Author: Martin Pouzar
 * License: GNU General Public License v3.0
 */

session_start();
require_once 'config.php';
require_once 'lang_helper.php';

requireAuth();

if (!checkPermission('admin')) {
    $_SESSION['error_msg'] = __('msg_access_denied');
    header('Location: index.php');
    exit;
}
if (isset($_GET['action']) && $_GET['action'] === 'health_status') {
    header('Content-Type: application/json');
    echo json_encode(getServiceHealthSummary());
    exit;
}
$pageData['title'] = __('health_page_title');
$page_title = __('health_page_title');

// ========== SYSTÉMOVÉ INFORMACE ==========

function getSystemInfo(): array {
    $loadAvg = sys_getloadavg();

    $memInfo = [];
    $memInfoRaw = file_get_contents('/proc/meminfo');
    if ($memInfoRaw !== false) {
        preg_match('/MemTotal:\s+(\d+)/', $memInfoRaw, $memTotal);
        preg_match('/MemAvailable:\s+(\d+)/', $memInfoRaw, $memAvailable);
        preg_match('/SwapTotal:\s+(\d+)/', $memInfoRaw, $swapTotal);
        preg_match('/SwapFree:\s+(\d+)/', $memInfoRaw, $swapFree);

        $memInfo['total'] = isset($memTotal[1]) ? (int)$memTotal[1] * 1024 : 0;
        $memInfo['available'] = isset($memAvailable[1]) ? (int)$memAvailable[1] * 1024 : 0;
        $memInfo['used'] = $memInfo['total'] - $memInfo['available'];
        $memInfo['used_percent'] = $memInfo['total'] > 0 ? round(($memInfo['used'] / $memInfo['total']) * 100, 1) : 0;

        $memInfo['swap_total'] = isset($swapTotal[1]) ? (int)$swapTotal[1] * 1024 : 0;
        $memInfo['swap_free'] = isset($swapFree[1]) ? (int)$swapFree[1] * 1024 : 0;
        $memInfo['swap_used'] = $memInfo['swap_total'] - $memInfo['swap_free'];
        $memInfo['swap_used_percent'] = $memInfo['swap_total'] > 0 ? round(($memInfo['swap_used'] / $memInfo['swap_total']) * 100, 1) : 0;
    }

    $diskInfo = [];

    // Získání seznamu všech připojených disků
    $mountsOutput = shell_exec('df -h --output=source,target,fstype,size,used,avail,pcent 2>/dev/null | tail -n +2');
    if ($mountsOutput !== null) {
        $lines = explode("\n", trim($mountsOutput));
        foreach ($lines as $line) {
            if (empty(trim($line))) continue;

            $parts = preg_split('/\s+/', trim($line));
            if (count($parts) < 7) continue;

            $device = $parts[0];
            $mount = $parts[1];
            $fstype = $parts[2];
            $sizeHuman = $parts[3];
            $usedHuman = $parts[4];
            $availHuman = $parts[5];
            $percentStr = $parts[6];

            // Filtrování jen fyzických disků a důležitých mount bodů
            if (strpos($device, '/dev/') !== 0 && strpos($device, '/') !== 0) continue;
            if (in_array($fstype, ['tmpfs', 'devtmpfs', 'squashfs', 'overlay'])) continue;

            $total = disk_total_space($mount);
            $free = disk_free_space($mount);

            if ($total !== false && $free !== false) {
                $used = $total - $free;
                $diskInfo[] = [
                    'device' => $device,
                    'mount' => $mount,
                    'fstype' => $fstype,
                    'total' => $total,
                    'used' => $used,
                    'free' => $free,
                    'used_percent' => $total > 0 ? round(($used / $total) * 100, 1) : 0,
                ];
            }
        }
    }

    $uptimeRaw = file_get_contents('/proc/uptime');
    $systemUptime = 'N/A';
    if ($uptimeRaw !== false) {
        $uptimeSeconds = (int)explode(' ', trim($uptimeRaw))[0];
        $systemUptime = formatUptime($uptimeSeconds);
    }

    $cpuCount = 0;
    $cpuInfo = file_get_contents('/proc/cpuinfo');
    if ($cpuInfo !== false) {
        preg_match_all('/^processor/m', $cpuInfo, $matches);
        $cpuCount = count($matches[0]);
    }

    return [
        'load_avg' => $loadAvg,
        'memory' => $memInfo,
        'disks' => $diskInfo,
        'uptime' => $systemUptime,
        'cpu_count' => $cpuCount,
    ];
}

// ========== HLAVNÍ KÓD ==========

$healthData = getServiceHealthData();
$services = $healthData['services'];
$serviceRows = $healthData['rows'];
$healthyCount = $healthData['healthy_count'];

$systemInfo = getSystemInfo();

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
                <h1><i class="fas fa-heartbeat"></i> <?php echo __('health_page_title'); ?></h1>
            </div>
                <!-- Statistiky systému -->
                <div class="stats-inline system-stats-inline">
                    <div class="stat-inline-item cpu">
                        <span class="stat-inline-label"><i class="fas fa-microchip"></i> <?php echo __('cpu_load'); ?></span>
                        <span class="stat-inline-value"><?php echo number_format($systemInfo['load_avg'][0], 2); ?></span>
                        <span class="stat-inline-sub">
                            5m: <?php echo number_format($systemInfo['load_avg'][1], 2); ?> | 
                            15m: <?php echo number_format($systemInfo['load_avg'][2], 2); ?> | 
                            <?php echo $systemInfo['cpu_count']; ?> cores
                        </span>
                    </div>

                    <div class="stat-inline-item memory <?php echo $systemInfo['memory']['used_percent'] > 80 ? 'danger' : 'success'; ?>">
                        <span class="stat-inline-label"><i class="fas fa-memory"></i> <?php echo __('memory_usage'); ?></span>
                        <span class="stat-inline-value"><?php echo $systemInfo['memory']['used_percent']; ?>%</span>
                        <span class="stat-inline-sub">
                            <?php echo formatBytes($systemInfo['memory']['used']); ?> / 
                            <?php echo formatBytes($systemInfo['memory']['total']); ?>
                        </span>
                    </div>

                    <?php if ($systemInfo['memory']['swap_total'] > 0): ?>
                    <div class="stat-inline-item swap <?php echo $systemInfo['memory']['swap_used_percent'] > 50 ? 'warning' : 'success'; ?>">
                        <span class="stat-inline-label"><i class="fas fa-exchange-alt"></i> <?php echo __('swap_usage'); ?></span>
                        <span class="stat-inline-value"><?php echo $systemInfo['memory']['swap_used_percent']; ?>%</span>
                        <span class="stat-inline-sub">
                            <?php echo formatBytes($systemInfo['memory']['swap_used']); ?> / 
                            <?php echo formatBytes($systemInfo['memory']['swap_total']); ?>
                        </span>
                    </div>
                    <?php endif; ?>

                    <div class="stat-inline-item uptime">
                        <span class="stat-inline-label"><i class="fas fa-clock"></i> <?php echo __('system_uptime'); ?></span>
                        <span class="stat-inline-value"><?php echo $systemInfo['uptime']; ?></span>
                    </div>

                    <div class="stat-inline-item services <?php echo $healthyCount === count($services) ? 'success' : 'danger'; ?>">
                        <span class="stat-inline-label"><i class="fas fa-server"></i> <?php echo __('services_status'); ?></span>
                        <span class="stat-inline-value"><?php echo $healthyCount; ?> / <?php echo count($services); ?></span>
                        <span class="stat-inline-sub"><?php echo __('services_healthy'); ?></span>
                    </div>
                </div>
        </div>
        <!-- Tabulka služeb -->
        <div class="card">
            <div class="card-header">
                <i class="fas fa-cogs"></i> <?php echo __('services_health'); ?>
            </div>

            <div class="table-container">
                <table class="messages-table health-services-table">
                    <thead>
                        <tr>
                            <th><i class="fas fa-server"></i> <?php echo __('service'); ?></th>
                            <th><i class="fas fa-info-circle"></i> <?php echo __('status'); ?></th>
                            <th><i class="fas fa-list-ol"></i> <?php echo __('processes'); ?></th>
                            <th><i class="fas fa-memory"></i> <?php echo __('memory'); ?></th>
                            <th><i class="fas fa-microchip"></i> <?php echo __('cpu'); ?></th>
                            <th><i class="fas fa-clock"></i> <?php echo __('uptime'); ?></th>
                            <th><i class="fas fa-redo"></i> <?php echo __('restarts'); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($serviceRows as $row): ?>
                        <tr class="service-row-<?php echo htmlspecialchars($row['state']); ?>">
                            <td>
                                <strong><?php echo htmlspecialchars($row['label']); ?></strong>
                            </td>
                            <td>
                                <?php
                                $badgeClass = 'badge-secondary';
                                if ($row['state'] === 'running') $badgeClass = 'badge-success';
                                elseif ($row['state'] === 'failed') $badgeClass = 'badge-danger';
                                elseif ($row['state'] === 'starting') $badgeClass = 'badge-warning';
                                ?>
                                <span class="badge <?php echo $badgeClass; ?>">
                                    <?php echo __('state_' . $row['state']); ?>
                                </span>
                            </td>
                            <td class="text-center">
                                <?php echo $row['process_count'] > 0 ? '<strong>' . $row['process_count'] . '</strong>' : '<span style="color: #bdc3c7;">-</span>'; ?>
                            </td>
                            <td><?php echo htmlspecialchars($row['memory_formatted']); ?></td>
                            <td class="text-center">
                                <?php 
                                if ($row['cpu_usage'] > 0) {
                                    $cpuColor = $row['cpu_usage'] > 50 ? '#e74c3c' : ($row['cpu_usage'] > 25 ? '#f39c12' : '#27ae60');
                                    echo '<strong style="color: ' . $cpuColor . ';">' . $row['cpu_usage'] . '%</strong>';
                                } else {
                                    echo '<span style="color: #bdc3c7;">-</span>';
                                }
                                ?>
                            </td>
                            <td><?php echo htmlspecialchars($row['uptime']); ?></td>
                            <td class="text-center">
                                <?php 
                                if ($row['restart_count'] > 0) {
                                    echo '<span class="badge badge-warning">' . $row['restart_count'] . '</span>';
                                } else {
                                    echo '<span style="color: #27ae60;">0</span>';
                                }
                                ?>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Tabulka disků -->
        <div class="card">
            <div class="card-header">
                <i class="fas fa-hdd"></i> <?php echo __('disk_usage'); ?>
            </div>

            <div class="table-container">
                <table class="messages-table">
                    <thead>
                        <tr>
                            <th><i class="fas fa-hdd"></i> <?php echo __('device'); ?></th>
                            <th><i class="fas fa-folder"></i> <?php echo __('mount_point'); ?></th>
                            <th><i class="fas fa-file-code"></i> <?php echo __('filesystem'); ?></th>
                            <th><i class="fas fa-database"></i> <?php echo __('total'); ?></th>
                            <th><i class="fas fa-chart-pie"></i> <?php echo __('used'); ?></th>
                            <th><i class="fas fa-inbox"></i> <?php echo __('free'); ?></th>
                            <th><i class="fas fa-percentage"></i> <?php echo __('usage'); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($systemInfo['disks'] as $disk): ?>
                        <tr>
                            <td><code><?php echo htmlspecialchars($disk['device']); ?></code></td>
                            <td><strong><?php echo htmlspecialchars($disk['mount']); ?></strong></td>
                            <td><span class="badge badge-secondary"><?php echo htmlspecialchars($disk['fstype']); ?></span></td>
                            <td><?php echo formatBytes($disk['total']); ?></td>
                            <td><?php echo formatBytes($disk['used']); ?></td>
                            <td><?php echo formatBytes($disk['free']); ?></td>
                            <td>
                                <?php
                                $percent = $disk['used_percent'];
                                $barColor = $percent > 90 ? '#e74c3c' : ($percent > 75 ? '#f39c12' : '#27ae60');
                                ?>
                                <div style="display: flex; align-items: center; gap: 10px;">
                                    <div style="flex: 1; background: #ecf0f1; border-radius: 10px; height: 10px; overflow: hidden;">
                                        <div style="width: <?php echo $percent; ?>%; background: <?php echo $barColor; ?>; height: 100%;"></div>
                                    </div>
                                    <strong style="color: <?php echo $barColor; ?>; min-width: 45px; text-align: right;">
                                        <?php echo $percent; ?>%
                                    </strong>
                                </div>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
</div>

<style>
/* Dodatečné styly pro health stránku */
.service-row-running {
    background-color: rgba(39, 174, 96, 0.05);
}

.service-row-failed {
    background-color: rgba(231, 76, 60, 0.08);
}

.service-row-stopped {
    background-color: rgba(149, 165, 166, 0.05);
}

.service-row-starting {
    background-color: rgba(243, 156, 18, 0.05);
}

.system-stats-inline {
    margin-bottom: 20px;
    gap: 12px;
}

.system-stats-inline .stat-inline-item {
    flex-wrap: wrap;
    gap: 6px 8px;
    padding: 6px 10px;
}

.system-stats-inline .stat-inline-sub {
    color: #7f8c8d;
    font-size: 11px;
    width: 100%;
}

.system-stats-inline .stat-inline-item.success {
    border-left-color: #27ae60;
}

.system-stats-inline .stat-inline-item.warning {
    border-left-color: #f39c12;
}

.system-stats-inline .stat-inline-item.danger {
    border-left-color: #e74c3c;
}

.health-services-table th,
.health-services-table td {
    padding: 6px 10px;
    line-height: 1.2;
    vertical-align: middle;
}

.health-services-table .badge {
    font-size: 11px;
    padding: 3px 6px;
}

code {
    background: #f8f9fa;
    padding: 2px 6px;
    border-radius: 3px;
    font-family: 'Courier New', monospace;
    font-size: 12px;
    color: #2c3e50;
}
</style>
