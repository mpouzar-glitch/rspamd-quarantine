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

$page_title = __('health_page_title', ['app' => __('app_title')]);

$systemctlAvailable = !empty(trim((string)shell_exec('command -v systemctl 2>/dev/null')));

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

function getServiceStatus(string $unit, bool $systemctlAvailable): array {
    if (!$systemctlAvailable) {
        return [
            'state' => 'unknown',
            'active' => '',
            'sub' => '',
            'detail' => __('health_systemctl_missing'),
        ];
    }

    $loadState = getSystemctlValue('LoadState', $unit);
    if ($loadState !== 'loaded') {
        return [
            'state' => 'missing',
            'active' => '',
            'sub' => '',
            'detail' => __('health_detail_missing'),
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

    $detail = __('health_detail_state', [
        'active' => $activeState !== '' ? $activeState : __('health_value_unknown'),
        'sub' => $subState !== '' ? $subState : __('health_value_unknown'),
    ]);

    return [
        'state' => $state,
        'active' => $activeState,
        'sub' => $subState,
        'detail' => $detail,
    ];
}

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
    ];
}

include 'menu.php';
?>
<!DOCTYPE html>
<html lang="<?php echo htmlspecialchars(currentLang()); ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($page_title); ?></title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <link rel="stylesheet" href="css/style.css">
    <style>
        .health-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 20px;
            gap: 20px;
            flex-wrap: wrap;
        }

        .health-header h1 {
            font-size: 24px;
            color: #2c3e50;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .health-summary {
            background: #f8f9fb;
            border: 1px solid #e0e6ed;
            padding: 10px 16px;
            border-radius: 8px;
            font-size: 14px;
            color: #34495e;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .health-table {
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }

        .health-table th,
        .health-table td {
            padding: 14px 16px;
            text-align: left;
            border-bottom: 1px solid #ecf0f1;
            font-size: 14px;
        }

        .health-table th {
            background: #f4f6f9;
            color: #2c3e50;
            font-weight: 600;
        }

        .status-pill {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 6px 10px;
            border-radius: 999px;
            font-size: 12px;
            font-weight: 600;
        }

        .status-ok {
            background: rgba(46, 204, 113, 0.15);
            color: #27ae60;
        }

        .status-warn {
            background: rgba(241, 196, 15, 0.15);
            color: #d35400;
        }

        .status-err {
            background: rgba(231, 76, 60, 0.15);
            color: #c0392b;
        }

        .status-unknown {
            background: rgba(149, 165, 166, 0.15);
            color: #7f8c8d;
        }

        .detail-text {
            color: #7f8c8d;
            font-size: 13px;
        }

        .health-meta {
            margin-top: 16px;
            font-size: 13px;
            color: #7f8c8d;
        }
    </style>
</head>
<body>
<div class="container">
    <div class="health-header">
        <h1><i class="fas fa-heart-pulse"></i> <?php echo htmlspecialchars(__('health_title')); ?></h1>
        <div class="health-summary">
            <i class="fas fa-check-circle"></i>
            <?php echo htmlspecialchars(__('health_summary', ['healthy' => $healthyCount, 'total' => count($serviceRows)])); ?>
        </div>
    </div>

    <p class="detail-text"><?php echo htmlspecialchars(__('health_subtitle')); ?></p>

    <table class="health-table">
        <thead>
            <tr>
                <th><?php echo htmlspecialchars(__('health_table_service')); ?></th>
                <th><?php echo htmlspecialchars(__('health_table_unit')); ?></th>
                <th><?php echo htmlspecialchars(__('health_table_status')); ?></th>
                <th><?php echo htmlspecialchars(__('health_table_health')); ?></th>
                <th><?php echo htmlspecialchars(__('health_table_details')); ?></th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($serviceRows as $row): ?>
                <?php
                $statusClass = match ($row['state']) {
                    'running' => 'status-ok',
                    'starting' => 'status-warn',
                    'stopped' => 'status-err',
                    'failed' => 'status-err',
                    'missing' => 'status-err',
                    default => 'status-unknown',
                };
                $statusLabel = match ($row['state']) {
                    'running' => __('health_status_running'),
                    'starting' => __('health_status_starting'),
                    'stopped' => __('health_status_stopped'),
                    'failed' => __('health_status_failed'),
                    'missing' => __('health_status_missing'),
                    default => __('health_status_unknown'),
                };
                $healthClass = match ($row['healthy']) {
                    'healthy' => 'status-ok',
                    'unhealthy' => 'status-err',
                    default => 'status-unknown',
                };
                $healthLabel = match ($row['healthy']) {
                    'healthy' => __('health_health_ok'),
                    'unhealthy' => __('health_health_bad'),
                    default => __('health_health_unknown'),
                };
                ?>
                <tr>
                    <td><?php echo htmlspecialchars($row['label']); ?></td>
                    <td><?php echo htmlspecialchars($row['unit']); ?></td>
                    <td>
                        <span class="status-pill <?php echo htmlspecialchars($statusClass); ?>">
                            <i class="fas fa-circle"></i>
                            <?php echo htmlspecialchars($statusLabel); ?>
                        </span>
                    </td>
                    <td>
                        <span class="status-pill <?php echo htmlspecialchars($healthClass); ?>">
                            <i class="fas fa-heart"></i>
                            <?php echo htmlspecialchars($healthLabel); ?>
                        </span>
                    </td>
                    <td class="detail-text"><?php echo htmlspecialchars($row['detail']); ?></td>
                </tr>
            <?php endforeach; ?>
        </tbody>
    </table>

    <div class="health-meta">
        <i class="far fa-clock"></i>
        <?php echo htmlspecialchars(__('health_checked_at', ['time' => date('d.m.Y H:i:s')])); ?>
    </div>
</div>
</body>
</html>
