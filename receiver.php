<?php
/*
 * Version: 2.0.0
 * Author: Martin Pouzar
 * License: GNU General Public License v3.0
 */
/**
 * Rspamd Quarantine Receiver
 * Version: 2.0.4
 * OPRAVENO: Recipients ukládány jako prostý text (bez JSON)
 */

require_once __DIR__ . '/config.php';

/**
 * Check if remote IP address is allowed to access receiver endpoints
 * @return bool True if IP is allowed, false otherwise
 */
function isAllowedReceiverIP(): bool {
    // Get real client IP address
    $client_ip = $_SERVER['REMOTE_ADDR'] ?? '';

    // Handle X-Forwarded-For if behind proxy (optional, be careful with this!)
    if (isset($_SERVER['HTTP_X_FORWARDED_FOR']) && !empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $forwarded_ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        $client_ip = trim($forwarded_ips[0]);
    }

    // Check if IP is in whitelist
    if (defined('RECEIVER_ALLOWED_IPS')) {
        $allowed_ips = RECEIVER_ALLOWED_IPS;

        // Check exact match
        if (in_array($client_ip, $allowed_ips, true)) {
            return true;
        }

        // Check CIDR ranges
        foreach ($allowed_ips as $allowed_ip) {
            // Check if it's a CIDR notation
            if (strpos($allowed_ip, '/') !== false) {
                if (ipInCIDR($client_ip, $allowed_ip)) {
                    return true;
                }
            }
        }
    }

    // Log unauthorized access attempt
    error_log(sprintf(
        'Unauthorized receiver access attempt from IP: %s (User-Agent: %s)',
        $client_ip,
        $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown'
    ));

    return false;
}

/**
 * Check if an IP address is within a CIDR range
 * @param string $ip IP address to check
 * @param string $cidr CIDR notation (e.g., 192.168.1.0/24)
 * @return bool
 */
function ipInCIDR(string $ip, string $cidr): bool {
    list($subnet, $mask) = explode('/', $cidr);

    // Convert IP addresses to long integers
    $ip_long = ip2long($ip);
    $subnet_long = ip2long($subnet);

    if ($ip_long === false || $subnet_long === false) {
        return false;
    }

    // Create mask
    $mask_long = -1 << (32 - (int)$mask);

    // Compare
    return ($ip_long & $mask_long) === ($subnet_long & $mask_long);
}

// Only accept POST requests
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    die('Method Not Allowed');
}

if (!isAllowedReceiverIP()) {
    http_response_code(403);
    echo json_encode([
        'status' => 'error',
        'message' => 'Access denied - IP not whitelisted'
    ]);
    exit;
}

// Get the raw message content
$message_content = file_get_contents('php://input');

if (empty($message_content)) {
    error_log('Receiver: Empty message content received');
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'Empty message']);
    exit;
}

// Get metadata from headers
$metadata = [
    'message_id' => $_SERVER['HTTP_X_RSPAMD_MESSAGE_ID'] ?? null,
    'queue_id' => $_SERVER['HTTP_X_RSPAMD_QUEUE_ID'] ?? null,
    'sender' => $_SERVER['HTTP_X_RSPAMD_FROM'] ?? null,
    'recipients_raw' => $_SERVER['HTTP_X_RSPAMD_RCPT'] ?? null,
    'ip' => $_SERVER['HTTP_X_RSPAMD_IP'] ?? null,
    'user' => $_SERVER['HTTP_X_RSPAMD_USER'] ?? null,
    'action' => $_SERVER['HTTP_X_RSPAMD_ACTION'] ?? null,
    'score' => $_SERVER['HTTP_X_RSPAMD_SCORE'] ?? null,
    'symbols' => $_SERVER['HTTP_X_RSPAMD_SYMBOLS'] ?? null,
];

// Parse recipients - remove JSON brackets and quotes
// Input může být: ["user@domain.com"] nebo "user@domain.com" nebo user@domain.com
$recipients = $metadata['recipients_raw'];
if ($recipients) {
    // Odstraníme [ ] { } " '
    $recipients = str_replace(['[', ']', '{', '}', '"', "'"], '', $recipients);
    // Oddělíme čárkami pokud je více příjemců
    $recipients = trim($recipients);
} else {
    $recipients = '';
}

// Parse email headers for additional metadata
$headers_end = strpos($message_content, "\r\n\r\n");
if ($headers_end === false) {
    $headers_end = strpos($message_content, "\n\n");
}

$headers = [];
if ($headers_end !== false) {
    $headers_text = substr($message_content, 0, $headers_end);

    preg_match('/^From:(.*)$/mi', $headers_text, $from_match);
    preg_match('/^To:(.*)$/mi', $headers_text, $to_match);
    preg_match('/^Subject:(.*)$/mi', $headers_text, $subject_match);
    preg_match('/^Date:(.*)$/mi', $headers_text, $date_match);
    preg_match('/^Received:(.*)$/mi', $headers_text, $received_match);

    $headers['from'] = isset($from_match[1]) ? trim($from_match[1]) : null;
    $headers['to'] = isset($to_match[1]) ? trim($to_match[1]) : null;
    $headers['subject'] = isset($subject_match[1]) ? trim($subject_match[1]) : null;
    $headers['date'] = isset($date_match[1]) ? trim($date_match[1]) : null;
    $headers['hostname'] = null;

    if (isset($received_match[1])) {
        if (preg_match('/\\bfrom\\s+([^\\s\\(\\);]+)/i', $received_match[1], $hostname_match)) {
            $headers['hostname'] = trim($hostname_match[1]);
        }
    }
}

try {
    $db = Database::getInstance()->getConnection();

    $stmt = $db->prepare("
        INSERT INTO quarantine_messages (
            message_id, queue_id, sender, recipients, subject,
            ip_address, authenticated_user, action, score, symbols,
            headers_from, headers_to, headers_date, hostname,
            message_content, metadata
        ) VALUES (
            :message_id, :queue_id, :sender, :recipients, :subject,
            :ip, :user, :action, :score, :symbols,
            :headers_from, :headers_to, :headers_date, :hostname,
            :message_content, :metadata
        )
    ");

    $stmt->execute([
        ':message_id' => $metadata['message_id'],
        ':queue_id' => $metadata['queue_id'],
        ':sender' => $metadata['sender'],
        ':recipients' => $recipients, // OPRAVENO: bez JSON formátu
        ':subject' => $headers['subject'],
        ':ip' => $metadata['ip'],
        ':user' => $metadata['user'],
        ':action' => $metadata['action'],
        ':score' => $metadata['score'],
        ':symbols' => $metadata['symbols'],
        ':headers_from' => $headers['from'],
        ':headers_to' => $headers['to'],
        ':headers_date' => $headers['date'],
        ':hostname' => $headers['hostname'],
        ':message_content' => $message_content,
        ':metadata' => json_encode(array_merge($metadata, $headers))
    ]);

    $quarantine_id = $db->lastInsertId();

    // Log to trace
    $stmt = $db->prepare("
        INSERT INTO trace_log (quarantine_id, action, user, details)
        VALUES (:qid, 'quarantined', 'system', :details)
    ");

    $stmt->execute([
        ':qid' => $quarantine_id,
        ':details' => sprintf('Message quarantined: %s from %s to %s (score: %s, action: %s)',
            $metadata['message_id'], $metadata['sender'], $recipients, 
            $metadata['score'], $metadata['action'])
    ]);

    //error_log(sprintf('Message quarantined: ID=%d, MessageID=%s, From=%s, To=%s', $quarantine_id, $metadata['message_id'], $metadata['sender'], $recipients));

    http_response_code(200);
    echo json_encode(['status' => 'ok', 'id' => $quarantine_id]);

} catch (PDOException $e) {
    error_log('Database error in receiver: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Database error']);
}
?>
