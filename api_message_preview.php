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
$format = $_GET['format'] ?? 'text'; // 'text' or 'html'

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

                    if (preg_match('/Content-Transfer-Encoding:\s*(\S+)/i', $part_headers, $enc_match)) {
                        $part_encoding = strtolower(trim($enc_match[1]));
                        if ($part_encoding === 'base64') {
                            $part_body = base64_decode($part_body);
                        } elseif ($part_encoding === 'quoted-printable') {
                            $part_body = quoted_printable_decode($part_body);
                        }
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

    // Prepare preview based on format
    $preview = '';
    $is_html_preview = false;

    if ($format === 'html' && !empty($body_html)) {
        // HTML preview with sanitization
        $preview = $body_html;

        // Remove dangerous tags and attributes
        $preview = preg_replace('/<script\b[^>]*>.*?<\/script>/is', '', $preview);
        $preview = preg_replace('/<style\b[^>]*>.*?<\/style>/is', '', $preview);
        $preview = preg_replace('/on\w+\s*=\s*["\x27][^"\x27]*["\x27]/i', '', $preview);
        $preview = preg_replace('/on\w+\s*=\s*\S+/i', '', $preview);
        $preview = preg_replace('/<iframe\b[^>]*>.*?<\/iframe>/is', '', $preview);
        $preview = preg_replace('/<object\b[^>]*>.*?<\/object>/is', '', $preview);
        $preview = preg_replace('/<embed\b[^>]*>/is', '', $preview);
        $preview = preg_replace('/<link\b[^>]*>/is', '', $preview);

        // Convert absolute URLs to prevent tracking
        $preview = preg_replace('/(src|href)\s*=\s*["\x27]https?:\/\/[^"\x27]*["\x27]/i', '$1="#blocked"', $preview);

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
    if (!$is_html_preview && mb_strlen($preview, 'UTF-8') > 300) {
        $preview = mb_substr($preview, 0, 300, 'UTF-8') . '...';
    } elseif ($is_html_preview && mb_strlen($preview, 'UTF-8') > 5000) {
        $preview = mb_substr($preview, 0, 5000, 'UTF-8') . '<p>... (zkráceno)</p>';
    }

    echo json_encode([
        'success' => true,
        'preview' => $preview,
        'is_html' => $is_html_preview,
        'has_html' => !empty($body_html),
        'has_text' => !empty($body_text),
        'sender' => decodeMimeHeader($message['sender']),
        'subject' => decodeMimeHeader($message['subject']) ?: '(bez předmětu)',
        'timestamp' => date('d.m.Y H:i:s', strtotime($message['timestamp'])),
        'score' => round($message['score'], 2)
    ]);

} catch (Exception $e) {
    error_log('Message preview error: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['error' => 'Chyba serveru: ' . $e->getMessage()]);
}
