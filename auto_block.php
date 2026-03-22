<?php
/*
 * Rspamd Quarantine – Auto-Block Spam IPs
 * Version: 1.0.0
 * Author: Martin Pouzar
 * License: GNU General Public License v3.0
 *
 * Detects IP addresses that repeatedly send spam within a configurable time
 * window and blocks them via CrowdSec.
 *
*/

require_once __DIR__ . '/config.php';

$db = Database::getInstance()->getConnection();

// ============================================
// CrowdSec block helper
// Defined here so this script works standalone
// (operations.php requires web auth)
// ============================================
if (!function_exists('blockIpAddress')) {
    function blockIpAddress($ip, $duration = '8h', $reason = 'force-denied', $source = 'rspamd') {
        if (!defined('CROWDSEC_API_URL') || !defined('CROWDSEC_API_KEY')) {
            return ['success' => false, 'error' => 'CrowdSec API není nakonfigurováno'];
        }

        $data = [
            'ip'       => $ip,
            'duration' => $duration,
            'reason'   => $reason,
            'type'     => 'ban',
            'source'   => $source,
        ];

        $ch = curl_init(CROWDSEC_API_URL);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Content-Type: application/json',
            'X-Api-Key: ' . CROWDSEC_API_KEY,
        ]);

        $response   = curl_exec($ch);
        $http_code  = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curl_error = curl_error($ch);
        curl_close($ch);

        if ($curl_error) {
            return ['success' => false, 'error' => 'Curl error: ' . $curl_error];
        }

        if ($http_code < 200 || $http_code >= 300) {
            return ['success' => false, 'error' => 'HTTP ' . $http_code . ': ' . $response];
        }

        return ['success' => true];
    }
}

// ============================================
// Auto-block logic
// ============================================

if (!defined('AUTO_BLOCK_ENABLED') || !AUTO_BLOCK_ENABLED) {
    echo "[auto_block] Disabled in config – exiting.\n";
    exit(0);
}

$min_messages      = defined('AUTO_BLOCK_MIN_MESSAGES')      ? (int)AUTO_BLOCK_MIN_MESSAGES      : 10;
$time_window_hours = defined('AUTO_BLOCK_TIME_WINDOW_HOURS') ? (int)AUTO_BLOCK_TIME_WINDOW_HOURS : 24;
$min_score         = defined('AUTO_BLOCK_MIN_SCORE')         ? (float)AUTO_BLOCK_MIN_SCORE        : 10.0;
$block_duration    = defined('AUTO_BLOCK_DURATION')          ? AUTO_BLOCK_DURATION                : '48h';

// Combined IP exclusion: user-defined list + receiver whitelist
$exclude_ips = defined('AUTO_BLOCK_EXCLUDE_IPS') ? (array)AUTO_BLOCK_EXCLUDE_IPS : [];
if (defined('RECEIVER_ALLOWED_IPS')) {
    $exclude_ips = array_merge($exclude_ips, (array)RECEIVER_ALLOWED_IPS);
}
$exclude_ips = array_unique(array_filter($exclude_ips));

$cutoff = (new DateTimeImmutable('now'))
    ->modify('-' . $time_window_hours . ' hours')
    ->format('Y-m-d H:i:s');

echo sprintf(
    "[auto_block] Starting – window: %dh (since %s), min_msgs: %d, min_score: %.1f, ban: %s\n",
    $time_window_hours, $cutoff, $min_messages, $min_score, $block_duration
);

// Find IPs that exceeded the spam threshold within the time window
$sql = '
    SELECT ip_address, COUNT(*) AS spam_count
    FROM quarantine_messages
    WHERE timestamp  >= :cutoff
      AND ip_address IS NOT NULL
      AND ip_address  != \'\'
      AND score       >= :min_score
    GROUP BY ip_address
    HAVING spam_count >= :min_messages
    ORDER BY spam_count DESC
';

$stmt = $db->prepare($sql);
$stmt->execute([
    'cutoff'       => $cutoff,
    'min_score'    => $min_score,
    'min_messages' => $min_messages,
]);

$candidates = $stmt->fetchAll(PDO::FETCH_ASSOC);

if (empty($candidates)) {
    echo "[auto_block] No IPs exceeded the threshold – nothing to block.\n";
    exit(0);
}

echo sprintf("[auto_block] Found %d candidate IP(s).\n", count($candidates));

$blocked = 0;
$skipped = 0;
$errors  = 0;

foreach ($candidates as $row) {
    $ip         = $row['ip_address'];
    $spam_count = (int)$row['spam_count'];

    if (in_array($ip, $exclude_ips, true)) {
        echo sprintf("[auto_block] SKIP     %s – %d msgs (in exclusion list)\n", $ip, $spam_count);
        $skipped++;
        continue;
    }

    $result = blockIpAddress($ip, $block_duration, 'auto-spam-block', 'rspamd-quarantine');

    if ($result['success']) {
        echo sprintf(
            "[auto_block] BLOCKED  %s – %d spam msgs in last %dh (ban: %s)\n",
            $ip, $spam_count, $time_window_hours, $block_duration
        );
        $blocked++;
    } else {
        echo sprintf("[auto_block] ERROR    %s – %s\n", $ip, $result['error']);
        $errors++;
    }
}

echo sprintf(
    "[auto_block] Done – blocked: %d, skipped: %d, errors: %d\n",
    $blocked, $skipped, $errors
);
