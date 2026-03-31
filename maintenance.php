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
        // quarantine_message_blob se vymaže automaticky přes ON DELETE CASCADE
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

// message_trace: pokud je tabulka particionována, mazat přes DROP PARTITION (O(1)).
// Pokud partitioning ještě neproběhl, fallback na regulérní DELETE.

$is_partitioned = (bool) $db->query(
    "SELECT COUNT(*) FROM information_schema.PARTITIONS
     WHERE TABLE_SCHEMA = DATABASE()
       AND TABLE_NAME = 'message_trace'
       AND PARTITION_METHOD IS NOT NULL
       AND PARTITION_NAME IS NOT NULL"
)->fetchColumn();

if ($is_partitioned) {
    // Načti všechny pojmenované partition (ne pmax) a filtruj v PHP.
    // Vyhýbáme se PARTITION_DESCRIPTION — jeho formát závisí na verzi MariaDB.
    // Partice jsou pojmenovány pYYYY_MM; jejich boundary je první den následujícího měsíce.
    // Pokud boundary <= cutoff, celá partice obsahuje pouze expirovaná data.
    $all_partitions = $db->query(
        "SELECT PARTITION_NAME FROM information_schema.PARTITIONS
         WHERE TABLE_SCHEMA = DATABASE()
           AND TABLE_NAME = 'message_trace'
           AND PARTITION_NAME NOT IN ('pmax')
           AND PARTITION_NAME REGEXP '^p[0-9]{4}_[0-9]{2}$'"
    )->fetchAll(PDO::FETCH_COLUMN);

    $old_partitions = array_filter($all_partitions, function (string $name) use ($trace_cutoff): bool {
        // Název: p2025_01 → rok=2025, měsíc=01 → boundary = 2025-02-01
        preg_match('/^p(\d{4})_(\d{2})$/', $name, $m);
        $year  = (int) $m[1];
        $month = (int) $m[2] + 1;
        if ($month > 12) { $month = 1; $year++; }
        $boundary = sprintf('%04d-%02d-01', $year, $month);
        return $boundary <= $trace_cutoff;
    });

    if (!empty($old_partitions)) {
        $partition_list = implode(', ', array_map(fn(string $p) => "`$p`", $old_partitions));
        $db->exec("ALTER TABLE `message_trace` DROP PARTITION $partition_list");
        echo sprintf("[message_trace] Dropped %d partition(s): %s (cutoff: %s)\n",
            count($old_partitions),
            implode(', ', $old_partitions),
            $trace_cutoff
        );
    }

    // Vždy spusť DELETE pro zbývající expirovaná data v hraniční partici.
    // Partition pruning zajistí, že MariaDB prohledá jen relevantní partition(s) —
    // pokud byly starší celé partice právě dropnuty, jde o rychlý scan minimálního rozsahu.
    $stmt = $db->prepare('DELETE FROM `message_trace` WHERE `timestamp` < :cutoff');
    $stmt->execute(['cutoff' => $trace_cutoff]);
    $deleted_rows = $stmt->rowCount();
    if ($deleted_rows > 0) {
        echo sprintf("[message_trace] Deleted %d remaining row(s) via DELETE (cutoff: %s)\n",
            $deleted_rows,
            $trace_cutoff
        );
    } else {
        echo sprintf("[message_trace] No remaining rows to delete (cutoff: %s)\n", $trace_cutoff);
    }
} else {
    // Partitioning ještě nebyl aplikován — použij klasický DELETE
    $stmt = $db->prepare('DELETE FROM `message_trace` WHERE `timestamp` < :cutoff');
    $stmt->execute(['cutoff' => $trace_cutoff]);
    echo sprintf("[message_trace] Deleted %d rows via DELETE (cutoff: %s)\n",
        $stmt->rowCount(),
        $trace_cutoff
    );
}