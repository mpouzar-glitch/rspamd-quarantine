<?php
/**
 * API endpoint for message preview
 * Returns message content with HTML rendering option
 */

session_start();
require_once 'config.php';
require_once 'functions.php';

header('Content-Type: application/json');

if (!isAuthenticated()) {
    http_response_code(401);
    echo json_encode(['error' => 'Neautorizováno']);
    exit;
}

$msg_id = $_GET['id'] ?? '';
$format = $_GET['format'] ?? 'auto'; // 'auto', 'text' or 'html'

if (empty($msg_id)) {
    http_response_code(400);
    echo json_encode(['error' => 'Chybí ID zprávy']);
    exit;
}

try {
    $db = Database::getInstance()->getConnection();

    $params = [$msg_id];
    $domainFilter = getDomainFilterSQL($params);

    $sql = "SELECT * FROM quarantine_messages WHERE id = ? AND $domainFilter LIMIT 1";

    $stmt = $db->prepare($sql);
    $stmt->execute($params);
    $message = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$message) {
        http_response_code(404);
        echo json_encode(['error' => 'Zpráva nenalezena']);
        exit;
    }

    // Parse message
    $headers_end = strpos($message['message_content'], "\r\n\r\n");
    if ($headers_end === false) {
        $headers_end = strpos($message['message_content'], "\n\n");
    }

    $headers_raw = '';
    $body_raw = '';

    if ($headers_end !== false) {
        $headers_raw = substr($message['message_content'], 0, $headers_end);
        $body_raw = substr($message['message_content'], $headers_end + 4);
    } else {
        $headers_raw = $message['message_content'];
    }

    // Parse headers
    $headers_array = [];
    $lines = explode("\n", $headers_raw);
    $current_header = '';

    foreach ($lines as $line) {
        $line = rtrim($line, "\r");

        if (preg_match('/^[\s\t]/', $line) && $current_header) {
            $headers_array[$current_header] .= ' ' . trim($line);
        } else {
            if (preg_match('/^([^:]+):\s*(.*)$/', $line, $matches)) {
                $current_header = $matches[1];
                $headers_array[$current_header] = $matches[2];
            }
        }
    }

    $headers_lower = array_change_key_case($headers_array, CASE_LOWER);
    $dkim_header = $headers_lower['dkim-signature'] ?? '';
    $authentication_results = $headers_lower['authentication-results'] ?? '';
    $dmarc_header = $headers_lower['dmarc-filter'] ?? ($authentication_results ?: '');
    $spam_header = $headers_lower['x-spam-status'] ?? $headers_lower['x-spam-flag'] ?? $headers_lower['x-spam-level'] ?? $headers_lower['x-spam-score'] ?? '';
    $user_agent_header = $headers_lower['user-agent'] ?? $headers_lower['x-mailer'] ?? '';
    $from_header = $headers_lower['from'] ?? '';
    $to_header = $headers_lower['to'] ?? '';

    $content_type = $headers_array['Content-Type'] ?? 'text/plain';
    $is_html = stripos($content_type, 'text/html') !== false;
    $is_multipart = stripos($content_type, 'multipart') !== false;

    // Extract charset
    $charset = 'UTF-8';
    if (preg_match('/charset\s*=\s*["\x27]?([^"\x27 \s;]+)/i', $content_type, $matches)) {
        $charset = strtoupper($matches[1]);
    }

    // Decode body
    $content_encoding = strtolower($headers_array['Content-Transfer-Encoding'] ?? '');
    $body_decoded = $body_raw;

    if ($content_encoding === 'base64') {
        $body_decoded = base64_decode($body_raw);
    } elseif ($content_encoding === 'quoted-printable') {
        $body_decoded = quoted_printable_decode($body_raw);
    }

    // Convert charset
    if ($charset !== 'UTF-8' && $charset !== 'US-ASCII') {
        $body_decoded = @iconv($charset, 'UTF-8//IGNORE', $body_decoded) ?: $body_decoded;
    }

    $looksLikeHtml = function (string $value): bool {
        return preg_match('/<\/?(html|body|head|table|div|span|p|br|img|a)\b/i', $value) === 1;
    };

    // Handle multipart
    $body_text = '';
    $body_html = '';

    if ($is_multipart) {
        if (preg_match('/boundary\s*=\s*["\x27]?([^"\x27 \s;]+)/i', $content_type, $matches)) {
            $boundary = $matches[1];
            $parts = explode("--$boundary", $body_decoded);

            foreach ($parts as $part) {
                if (trim($part) === '' || trim($part) === '--') continue;

                $part_headers_end = strpos($part, "\r\n\r\n");
                if ($part_headers_end === false) {
                    $part_headers_end = strpos($part, "\n\n");
                }
                if ($part_headers_end === false) continue;

                $part_headers = substr($part, 0, $part_headers_end);
                $part_body = substr($part, $part_headers_end + 4);

                if (preg_match('/Content-Type:\s*([^\r\n;]+)/i', $part_headers, $ct_match)) {
                    $part_type = trim($ct_match[1]);
                    $part_charset = 'UTF-8';
                    if (preg_match('/charset\s*=\s*["\x27]?([^"\x27 \s;]+)/i', $part_headers, $charset_match)) {
                        $part_charset = strtoupper($charset_match[1]);
                    }

                    if (preg_match('/Content-Transfer-Encoding:\s*(\S+)/i', $part_headers, $enc_match)) {
                        $part_encoding = strtolower(trim($enc_match[1]));
                        if ($part_encoding === 'base64') {
                            $part_body = base64_decode($part_body);
                        } elseif ($part_encoding === 'quoted-printable') {
                            $part_body = quoted_printable_decode($part_body);
                        }
                    }

                    if (!in_array($part_charset, ['UTF-8', 'US-ASCII'], true)) {
                        $part_body = @iconv($part_charset, 'UTF-8//IGNORE', $part_body) ?: $part_body;
                    }

                    if (stripos($part_type, 'text/plain') !== false) {
                        $body_text = $part_body;
                    } elseif (stripos($part_type, 'text/html') !== false) {
                        $body_html = $part_body;
                    }
                }
            }
        }
    } else {
        if ($is_html) {
            $body_html = $body_decoded;
        } else {
            $body_text = $body_decoded;
        }
    }

    if (empty($body_html) && !empty($body_text) && $looksLikeHtml($body_text)) {
        $body_html = $body_text;
        $body_text = strip_tags($body_text);
    }

    // Prepare preview based on format
    $preview = '';
    $is_html_preview = false;

    $use_html = ($format === 'html' || ($format === 'auto' && !empty($body_html)));

    if ($use_html && !empty($body_html)) {
        // HTML preview with sanitization
        $preview = $body_html;

        // Remove dangerous tags and attributes
        $preview = preg_replace('/<script\b[^>]*>.*?<\/script>/is', '', $preview);
        $preview = preg_replace('/<style\b[^>]*>.*?<\/style>/is', '', $preview);
        $preview = preg_replace('/<meta\b[^>]*>/is', '', $preview);
        $preview = preg_replace('/<base\b[^>]*>/is', '', $preview);
        $preview = preg_replace('/on\w+\s*=\s*["\x27][^"\x27]*["\x27]/i', '', $preview);
        $preview = preg_replace('/on\w+\s*=\s*\S+/i', '', $preview);
        $preview = preg_replace('/<iframe\b[^>]*>.*?<\/iframe>/is', '', $preview);
        $preview = preg_replace('/<object\b[^>]*>.*?<\/object>/is', '', $preview);
        $preview = preg_replace('/<embed\b[^>]*>/is', '', $preview);
        $preview = preg_replace('/<link\b[^>]*>/is', '', $preview);
        $preview = preg_replace('/<form\b[^>]*>.*?<\/form>/is', '', $preview);

        // Convert absolute URLs to prevent tracking
        $preview = preg_replace('/\bsrc\s*=\s*["\x27][^"\x27]*["\x27]/i', 'src="#blocked"', $preview);
        $preview = preg_replace('/<a\b([^>]*?)\bhref\s*=\s*["\x27][^"\x27]*["\x27]/i', '<a$1href="#"', $preview);

        $is_html_preview = true;
    } else {
        // Text preview
        if (!empty($body_text)) {
            $preview = $body_text;
        } elseif (!empty($body_html)) {
            $preview = strip_tags($body_html);
        } else {
            $preview = '(náhled není dostupný)';
        }

        // Clean text
        $preview = html_entity_decode($preview, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $preview = preg_replace('/\s+/', ' ', $preview);
        $preview = trim($preview);
    }

    // Truncate if too long
    if (!$is_html_preview && mb_strlen($preview, 'UTF-8') > 2000) {
        $preview = mb_substr($preview, 0, 2000, 'UTF-8') . '...';
    } elseif ($is_html_preview && mb_strlen($preview, 'UTF-8') > 8000) {
        $preview = mb_substr($preview, 0, 8000, 'UTF-8') . '<p>... (zkráceno)</p>';
    }

    $subject_decoded = decodeMimeHeader($message['subject'] ?? $headers_array['Subject'] ?? '(bez předmětu)');
    $sender_decoded = decodeMimeHeader($message['sender'] ?? '');
    $recipients_decoded = decodeMimeHeader($message['recipients'] ?? '');
    $from_header_decoded = decodeMimeHeader($from_header);
    $to_header_decoded = decodeMimeHeader($to_header);

    $parsed_symbols = parseSymbolsForStats($message['symbols'] ?? '');
    $dkim_dmarc_symbols = array_values(array_filter($parsed_symbols, function ($sym) {
        $name = $sym['name'] ?? '';
        return stripos($name, 'dkim') !== false || stripos($name, 'dmarc') !== false;
    }));
    $dkim_present = !empty($dkim_header);
    $dmarc_present = !empty($dmarc_header) || array_filter($dkim_dmarc_symbols, fn($sym) => stripos($sym['name'], 'dmarc') !== false);

    echo json_encode([
        'success' => true,
        'preview' => $preview,
        'is_html' => $is_html_preview,
        'has_html' => !empty($body_html),
        'has_text' => !empty($body_text),
        'sender' => decodeMimeHeader($message['sender']),
        'subject' => $subject_decoded ?: '(bez předmětu)',
        'timestamp' => date('d.m.Y H:i:s', strtotime($message['timestamp'])),
        'score' => round($message['score'], 2),
        'message_id' => $message['message_id'] ?? '',
        'recipients' => $recipients_decoded,
        'from_header' => $from_header_decoded,
        'to_header' => $to_header_decoded,
        'dkim_present' => $dkim_present,
        'dmarc_present' => $dmarc_present,
        'dkim_dmarc_symbols' => $dkim_dmarc_symbols,
        'spam_header' => $spam_header,
        'user_agent' => $user_agent_header,
        'ip_address' => $message['ip_address'] ?? '',
        'authenticated_user' => $message['authenticated_user'] ?? '',
        'action' => $message['action'] ?? '',
        'state' => isset($message['state']) ? (int)$message['state'] : 0,
        'state_at' => $message['state_at'] ?? '',
        'state_by' => $message['state_by'] ?? '',
        'subject_decoded' => $subject_decoded,
        'sender_decoded' => $sender_decoded,
        'recipients_decoded' => $recipients_decoded
    ]);

} catch (Exception $e) {
    error_log('Message preview error: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['error' => 'Chyba serveru: ' . $e->getMessage()]);
}
