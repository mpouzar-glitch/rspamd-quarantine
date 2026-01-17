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
$pageData['title'] = __('health_page_title');
$page_title = __('health_page_title');

$systemctlAvailable = !empty(trim((string)shell_exec('command -v systemctl 2>/dev/null')));

// ========== FUNKCE PRO SYSTEMCTL ==========

function getSystemctlValue(string $property, string $unit): string {
    $command = sprintf(
        'systemctl show -p %s --value %s 2>/dev/null',
        escapeshellarg($property),
        escapeshellarg($unit)
    );
    return trim((string)shell_exec($command));
}

function resolveServiceUnit(array $units, bool $systemctlAvailable): string {
    if (!$systemctlAvailable) {
        return $units[0];
    }
    foreach ($units as $unit) {
        $loadState = getSystemctlValue('LoadState', $unit);
        if ($loadState === 'loaded') {
            return $unit;
        }
    }
    return $units[0];
}

// ========== ROZŠÍŘENÁ FUNKCE PRO STATUS SLUŽBY ==========

function getServiceStatus(string $unit, bool $systemctlAvailable): array {
    if (!$systemctlAvailable) {
        return [
            'state' => 'unknown',
            'active' => '',
            'sub' => '',
            'detail' => __('health_systemctl_missing'),
            'memory' => 0,
            'memory_formatted' => 'N/A',
            'process_count' => 0,
            'cpu_usage' => 0,
            'uptime' => 'N/A',
            'restart_count' => 0,
        ];
    }

    $loadState = getSystemctlValue('LoadState', $unit);
    if ($loadState !== 'loaded') {
        return [
            'state' => 'missing',
            'active' => '',
            'sub' => '',
            'detail' => __('health_detail_missing'),
            'memory' => 0,
            'memory_formatted' => 'N/A',
            'process_count' => 0,
            'cpu_usage' => 0,
            'uptime' => 'N/A',
            'restart_count' => 0,
        ];
    }

    $activeState = getSystemctlValue('ActiveState', $unit);
    $subState = getSystemctlValue('SubState', $unit);

    if ($activeState === 'active') {
        $state = 'running';
    } elseif ($activeState === 'activating') {
        $state = 'starting';
    } elseif ($activeState === 'inactive') {
        $state = 'stopped';
    } elseif ($activeState === 'failed') {
        $state = 'failed';
    } else {
        $state = 'unknown';
    }

    $memoryCurrent = getSystemctlValue('MemoryCurrent', $unit);
    $memory = $memoryCurrent !== '' && $memoryCurrent !== '[not set]' ? (int)$memoryCurrent : 0;
    $memoryFormatted = formatBytes($memory);

    $mainPID = getSystemctlValue('MainPID', $unit);
    $processCount = 0;

    if ($mainPID !== '' && $mainPID !== '0' && $mainPID !== '[not set]') {
        $processName = trim((string)shell_exec("ps -p " . escapeshellarg($mainPID) . " -o comm= 2>/dev/null"));
        if ($processName !== '') {
            $processCount = (int)trim((string)shell_exec("pgrep -c '^" . escapeshellarg($processName) . "$' 2>/dev/null || echo 0"));
        }
    }

    $cpuUsage = 0;
    if ($mainPID !== '' && $mainPID !== '0' && $mainPID !== '[not set]') {
        $processName = trim((string)shell_exec("ps -p " . escapeshellarg($mainPID) . " -o comm= 2>/dev/null"));
        if ($processName !== '') {
            $cpuOutput = trim((string)shell_exec("ps -C " . escapeshellarg($processName) . " -o %cpu= 2>/dev/null | awk '{s+=\$1} END {print s}'"));
            $cpuUsage = $cpuOutput !== '' ? round((float)$cpuOutput, 1) : 0;
        }
    }

    $activeEnterTimestamp = getSystemctlValue('ActiveEnterTimestamp', $unit);
    $uptime = 'N/A';
    if ($activeEnterTimestamp !== '' && $activeEnterTimestamp !== '[not set]' && $state === 'running') {
        $startTime = strtotime($activeEnterTimestamp);
        if ($startTime !== false) {
            $uptimeSeconds = time() - $startTime;
            $uptime = formatUptime($uptimeSeconds);
        }
    }

    $restartCount = getSystemctlValue('NRestarts', $unit);
    $restartCount = $restartCount !== '' && $restartCount !== '[not set]' ? (int)$restartCount : 0;

    $detail = __('health_detail_state', [
        'active' => $activeState !== '' ? $activeState : __('health_value_unknown'),
        'sub' => $subState !== '' ? $subState : __('health_value_unknown'),
    ]);

    return [
        'state' => $state,
        'active' => $activeState,
        'sub' => $subState,
        'detail' => $detail,
        'memory' => $memory,
        'memory_formatted' => $memoryFormatted,
        'process_count' => $processCount,
        'cpu_usage' => $cpuUsage,
        'uptime' => $uptime,
        'restart_count' => $restartCount,
    ];
}

// ========== POMOCNÉ FUNKCE ==========

function formatBytes(int $bytes): string {
    if ($bytes === 0) return '0 B';
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    $power = floor(log($bytes, 1024));
    return round($bytes / pow(1024, $power), 2) . ' ' . $units[$power];
}

function formatUptime(int $seconds): string {
    $days = floor($seconds / 86400);
    $hours = floor(($seconds % 86400) / 3600);
    $minutes = floor(($seconds % 3600) / 60);

    $parts = [];
    if ($days > 0) $parts[] = $days . 'd';
    if ($hours > 0) $parts[] = $hours . 'h';
    if ($minutes > 0) $parts[] = $minutes . 'm';

    return !empty($parts) ? implode(' ', $parts) : '< 1m';
}

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

$services = [
    [
        'label' => __('service_postfix'),
        'units' => ['postfix.service', 'postfix'],
    ],
    [
        'label' => __('service_dovecot'),
        'units' => ['dovecot.service', 'dovecot'],
    ],
    [
        'label' => __('service_nginx'),
        'units' => ['nginx.service', 'nginx'],
    ],
    [
        'label' => __('service_rspamd'),
        'units' => ['rspamd.service', 'rspamd'],
    ],
    [
        'label' => __('service_eset_efs'),
        'units' => ['efs.service', 'eset-efs.service', 'esets.service', 'efs', 'eset-efs', 'esets'],
    ],
    [
        'label' => __('service_clamav'),
        'units' => ['clamav-daemon.service', 'clamd.service', 'clamav-daemon', 'clamd'],
    ],
];

$serviceRows = [];
$healthyCount = 0;

foreach ($services as $service) {
    $unit = resolveServiceUnit($service['units'], $systemctlAvailable);
    $status = getServiceStatus($unit, $systemctlAvailable);
    $isHealthy = $status['state'] === 'running';

    if ($isHealthy) {
        $healthyCount++;
    }

    $serviceRows[] = [
        'label' => $service['label'],
        'unit' => $unit,
        'state' => $status['state'],
        'detail' => $status['detail'],
        'healthy' => $status['state'] === 'unknown' ? 'unknown' : ($isHealthy ? 'healthy' : 'unhealthy'),
        'memory' => $status['memory'],
        'memory_formatted' => $status['memory_formatted'],
        'process_count' => $status['process_count'],
        'cpu_usage' => $status['cpu_usage'],
        'uptime' => $status['uptime'],
        'restart_count' => $status['restart_count'],
    ];
}

$systemInfo = getSystemInfo();

include 'menu.php';
?>

<div class="container">
    <div class="page-header">
        <h1><i class="fas fa-heartbeat"></i> <?php echo __('health_page_title'); ?></h1>
        <p class="page-description"><?php echo __('health_page_description'); ?></p>
    </div>

    <!-- Statistiky systému -->
    <div class="stats-row">
        <div class="stat-box">
            <div class="stat-label"><i class="fas fa-microchip"></i> <?php echo __('cpu_load'); ?></div>
            <div class="stat-value"><?php echo number_format($systemInfo['load_avg'][0], 2); ?></div>
            <small style="color: #7f8c8d; font-size: 11px;">
                5m: <?php echo number_format($systemInfo['load_avg'][1], 2); ?> | 
                15m: <?php echo number_format($systemInfo['load_avg'][2], 2); ?> | 
                <?php echo $systemInfo['cpu_count']; ?> cores
            </small>
        </div>

        <div class="stat-box <?php echo $systemInfo['memory']['used_percent'] > 80 ? 'danger' : 'success'; ?>">
            <div class="stat-label"><i class="fas fa-memory"></i> <?php echo __('memory_usage'); ?></div>
            <div class="stat-value"><?php echo $systemInfo['memory']['used_percent']; ?>%</div>
            <small style="color: #7f8c8d; font-size: 11px;">
                <?php echo formatBytes($systemInfo['memory']['used']); ?> / 
                <?php echo formatBytes($systemInfo['memory']['total']); ?>
            </small>
        </div>

        <?php if ($systemInfo['memory']['swap_total'] > 0): ?>
        <div class="stat-box <?php echo $systemInfo['memory']['swap_used_percent'] > 50 ? 'warning' : 'success'; ?>">
            <div class="stat-label"><i class="fas fa-exchange-alt"></i> <?php echo __('swap_usage'); ?></div>
            <div class="stat-value"><?php echo $systemInfo['memory']['swap_used_percent']; ?>%</div>
            <small style="color: #7f8c8d; font-size: 11px;">
                <?php echo formatBytes($systemInfo['memory']['swap_used']); ?> / 
                <?php echo formatBytes($systemInfo['memory']['swap_total']); ?>
            </small>
        </div>
        <?php endif; ?>

        <div class="stat-box">
            <div class="stat-label"><i class="fas fa-clock"></i> <?php echo __('system_uptime'); ?></div>
            <div class="stat-value" style="font-size: 18px;"><?php echo $systemInfo['uptime']; ?></div>
        </div>

        <div class="stat-box <?php echo $healthyCount === count($services) ? 'success' : 'danger'; ?>">
            <div class="stat-label"><i class="fas fa-server"></i> <?php echo __('services_status'); ?></div>
            <div class="stat-value"><?php echo $healthyCount; ?> / <?php echo count($services); ?></div>
            <small style="color: #7f8c8d; font-size: 11px;"><?php echo __('services_healthy'); ?></small>
        </div>
    </div>

    <!-- Tabulka služeb -->
    <div class="card">
        <div class="card-header">
            <i class="fas fa-cogs"></i> <?php echo __('services_health'); ?>
        </div>

        <div class="table-container">
            <table class="messages-table">
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
                            <strong><?php echo htmlspecialchars($row['label']); ?></strong><br>
                            <small style="color: #7f8c8d;"><?php echo htmlspecialchars($row['unit']); ?></small>
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
                            </span><br>
                            <small style="color: #7f8c8d;"><?php echo htmlspecialchars($row['detail']); ?></small>
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

code {
    background: #f8f9fa;
    padding: 2px 6px;
    border-radius: 3px;
    font-family: 'Courier New', monospace;
    font-size: 12px;
    color: #2c3e50;
}
</style>
