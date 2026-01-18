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

    $splitHeadersBody = function (string $raw): array {
        $headers_end = strpos($raw, "\r\n\r\n");
        $separator_length = 4;
        if ($headers_end === false) {
            $headers_end = strpos($raw, "\n\n");
            $separator_length = 2;
        }

        if ($headers_end === false) {
            return [$raw, ''];
        }

        return [
            substr($raw, 0, $headers_end),
            substr($raw, $headers_end + $separator_length),
        ];
    };

    // Parse message
    [$headers_raw, $body_raw] = $splitHeadersBody($message['message_content']);

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

    $parseHeaders = function (string $raw): array {
        $headers = [];
        $lines = explode("\n", $raw);
        $current = '';

        foreach ($lines as $line) {
            $line = rtrim($line, "\r");
            if ($line === '') {
                continue;
            }
            if (preg_match('/^[\s\t]/', $line) && $current !== '') {
                $headers[$current] .= ' ' . trim($line);
                continue;
            }
            if (preg_match('/^([^:]+):\s*(.*)$/', $line, $matches)) {
                $current = strtolower(trim($matches[1]));
                $headers[$current] = $matches[2];
            }
        }

        return $headers;
    };

    $decodeBody = function (string $body, string $encoding): string {
        $encoding = strtolower($encoding);
        if ($encoding === 'base64') {
            return base64_decode($body);
        }
        if ($encoding === 'quoted-printable') {
            return quoted_printable_decode($body);
        }

        return $body;
    };

    $convertCharset = function (string $body, string $charset): string {
        $charset = strtoupper($charset);
        if (!in_array($charset, ['UTF-8', 'US-ASCII'], true)) {
            return @iconv($charset, 'UTF-8//IGNORE', $body) ?: $body;
        }

        return $body;
    };

    $extractCharset = function (string $contentType, string $fallback = 'UTF-8'): string {
        if (preg_match('/charset\s*=\s*["\x27]?([^"\x27 \s;]+)/i', $contentType, $matches)) {
            return strtoupper($matches[1]);
        }

        return $fallback;
    };

    $parseMimePart = function (array $headers, string $body) use (&$parseMimePart, $splitHeadersBody, $parseHeaders, $decodeBody, $convertCharset, $extractCharset): array {
        $content_type = $headers['content-type'] ?? 'text/plain';
        $content_encoding = $headers['content-transfer-encoding'] ?? '';

        if (stripos($content_type, 'multipart') !== false) {
            if (!preg_match('/boundary\s*=\s*["\x27]?([^"\x27 \s;]+)/i', $content_type, $matches)) {
                return ['text' => '', 'html' => ''];
            }

            $boundary = $matches[1];
            $parts = explode("--$boundary", $body);
            $body_text = '';
            $body_html = '';

            foreach ($parts as $part) {
                $part = ltrim($part);
                if ($part === '' || $part === '--') {
                    continue;
                }

                [$part_headers_raw, $part_body] = $splitHeadersBody($part);
                if ($part_body === '' && trim($part_headers_raw) === '') {
                    continue;
                }

                $part_headers = $parseHeaders($part_headers_raw);
                $parsed = $parseMimePart($part_headers, $part_body);

                if ($parsed['html'] !== '') {
                    $body_html = $parsed['html'];
                }
                if ($parsed['text'] !== '' && $body_text === '') {
                    $body_text = $parsed['text'];
                }
            }

            return ['text' => $body_text, 'html' => $body_html];
        }

        $decoded_body = $decodeBody($body, $content_encoding);
        $charset = $extractCharset($content_type, 'UTF-8');
        $decoded_body = $convertCharset($decoded_body, $charset);

        if (stripos($content_type, 'text/html') !== false) {
            return ['text' => '', 'html' => $decoded_body];
        }
        if (stripos($content_type, 'text/plain') !== false) {
            return ['text' => $decoded_body, 'html' => ''];
        }

        return ['text' => '', 'html' => ''];
    };

    $content_type = $headers_array['Content-Type'] ?? 'text/plain';
    $decoded_top_body = $decodeBody($body_raw, $headers_array['Content-Transfer-Encoding'] ?? '');
    $decoded_top_body = $convertCharset($decoded_top_body, $extractCharset($content_type, 'UTF-8'));
    $parsed_body = $parseMimePart($headers_lower, $decoded_top_body);
    $body_text = $parsed_body['text'];
    $body_html = $parsed_body['html'];

    $looksLikeHtml = function (string $value): bool {
        return preg_match('/<\/?(html|body|head|table|div|span|p|br|img|a)\b/i', $value) === 1;
    };

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
