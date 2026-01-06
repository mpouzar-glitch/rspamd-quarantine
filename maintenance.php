<?php
/*
 * Rspamd Quarantine Maintenance
 * Version: 2.0.0
 * Author: Martin Pouzar
 * License: GNU General Public License v3.0
 *
 * Run via cron to clean up old database records.
 */

require_once __DIR__ . '/config.php';

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    die('CLI only');
}

$db = Database::getInstance()->getConnection();

$now = new DateTimeImmutable('now');
$quarantine_cutoff = $now->modify('-' . QUARANTINE_RETENTION_DAYS . ' days')->format('Y-m-d H:i:s');
$trace_cutoff = $now->modify('-' . TRACE_RETENTION_DAYS . ' days')->format('Y-m-d H:i:s');
$audit_cutoff = $now->modify('-' . AUDIT_RETENTION_DAYS . ' days')->format('Y-m-d H:i:s');

$tasks = [
    [
        'label' => 'quarantine_messages',
        'sql' => 'DELETE FROM quarantine_messages WHERE timestamp < :cutoff',
        'params' => ['cutoff' => $quarantine_cutoff],
    ],
    [
        'label' => 'message_trace',
        'sql' => 'DELETE FROM message_trace WHERE timestamp < :cutoff',
        'params' => ['cutoff' => $trace_cutoff],
    ],
    [
        'label' => 'trace_log',
        'sql' => 'DELETE FROM trace_log WHERE timestamp < :cutoff',
        'params' => ['cutoff' => $trace_cutoff],
    ],
    [
        'label' => 'trace_statistics',
        'sql' => 'DELETE FROM trace_statistics WHERE date_hour < :cutoff',
        'params' => ['cutoff' => $trace_cutoff],
    ],
    [
        'label' => 'audit_log',
        'sql' => 'DELETE FROM audit_log WHERE timestamp < :cutoff',
        'params' => ['cutoff' => $audit_cutoff],
    ],
];

foreach ($tasks as $task) {
    $stmt = $db->prepare($task['sql']);
    $stmt->execute($task['params']);
    $deleted = $stmt->rowCount();

    echo sprintf(
        "[%s] Deleted %d rows (cutoff: %s)\n",
        $task['label'],
        $deleted,
        $task['params']['cutoff']
    );
}