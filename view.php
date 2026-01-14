<?php
session_start();
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/lang_helper.php';

// Authentication check
if (AUTH_ENABLED && !isset($_SESSION['authenticated'])) {
    header('Location: index.php');
    exit;
}

// Get message ID
$id = isset($_GET['id']) ? intval($_GET['id']) : 0;

if ($id <= 0) {
    die(__('view_invalid_message_id'));
}

$db = Database::getInstance()->getConnection();

// Get message details
$stmt = $db->prepare("
    SELECT * FROM quarantine_messages WHERE id = ?
");
$stmt->execute([$id]);
$message = $stmt->fetch();

if (!$message) {
    die(__('msg_not_found'));
}

if (!canAccessQuarantineMessage($message)) {
    http_response_code(403);
    die(__('users_access_denied'));
}

// Parse message headers
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

// Parse individual headers
$headers_array = [];
$lines = explode("\n", $headers_raw);
$current_header = '';

foreach ($lines as $line) {
    $line = rtrim($line, "\r");
    
    // Continuation line (starts with space or tab)
    if (preg_match('/^[\s\t]/', $line) && $current_header) {
        $headers_array[$current_header] .= ' ' . trim($line);
    } else {
        // New header
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

// Decode subject and from
$subject_decoded = decodeMimeHeader($message['subject'] ?? $headers_array['Subject'] ?? __('msg_no_subject'));
$from_decoded = decodeMimeHeader($headers_array['From'] ?? $message['sender'] ?? '');
$to_decoded = decodeMimeHeader($headers_array['To'] ?? $message['recipients'] ?? '');

// Parse body - detect content type and charset
$content_type = $headers_array['Content-Type'] ?? 'text/plain';
$is_html = stripos($content_type, 'text/html') !== false;
$is_multipart = stripos($content_type, 'multipart') !== false;

// Extract charset
$charset = 'UTF-8';
if (preg_match('/charset\s*=\s*["\']?([^"\'\s;]+)/i', $content_type, $matches)) {
    $charset = strtoupper($matches[1]);
}

// Decode body if base64 or quoted-printable
$content_encoding = strtolower($headers_array['Content-Transfer-Encoding'] ?? '');
$body_decoded = $body_raw;

if ($content_encoding === 'base64') {
    $body_decoded = base64_decode($body_raw);
} elseif ($content_encoding === 'quoted-printable') {
    $body_decoded = quoted_printable_decode($body_raw);
}

// Convert charset to UTF-8
if ($charset !== 'UTF-8' && $charset !== 'US-ASCII') {
    $body_decoded = @iconv($charset, 'UTF-8//IGNORE', $body_decoded) ?: $body_decoded;
}

// Handle multipart messages
$body_text = '';
$body_html = '';
$attachments = [];

function parsePartHeaders($raw_headers) {
    $headers = [];
    $lines = explode("\n", $raw_headers);
    $current_header = '';

    foreach ($lines as $line) {
        $line = rtrim($line, "\r");
        if (preg_match('/^[\s\t]/', $line) && $current_header) {
            $headers[$current_header] .= ' ' . trim($line);
        } else {
            if (preg_match('/^([^:]+):\s*(.*)$/', $line, $matches)) {
                $current_header = $matches[1];
                $headers[$current_header] = $matches[2];
            }
        }
    }

    return $headers;
}

function decodeAttachmentFilename($value) {
    $value = trim($value);
    $value = trim($value, "\"'");

    if (stripos($value, "''") !== false) {
        [$charset, $lang, $encoded] = array_pad(explode("''", $value, 3), 3, '');
        $decoded = rawurldecode($encoded);
        if (!empty($charset) && strtoupper($charset) !== 'UTF-8') {
            $decoded = @iconv($charset, 'UTF-8//IGNORE', $decoded) ?: $decoded;
        }
        $value = $decoded;
    }

    return decodeMimeHeader($value);
}

if ($is_multipart) {
    // Extract boundary
    if (preg_match('/boundary\s*=\s*["\']?([^"\'\s;]+)/i', $content_type, $matches)) {
        $boundary = $matches[1];
        $parts = explode("--$boundary", $body_decoded);
        
        foreach ($parts as $part) {
            if (trim($part) === '' || trim($part) === '--') continue;
            
            // Split part headers and body
            $part_headers_end = strpos($part, "\r\n\r\n");
            if ($part_headers_end === false) {
                $part_headers_end = strpos($part, "\n\n");
            }
            
            if ($part_headers_end === false) continue;
            
            $part_headers = substr($part, 0, $part_headers_end);
            $part_body = substr($part, $part_headers_end + 4);
            
            $part_headers_array = parsePartHeaders($part_headers);
            $part_content_type = $part_headers_array['Content-Type'] ?? 'text/plain';
            $part_disposition = $part_headers_array['Content-Disposition'] ?? '';
            $part_type = trim(preg_split('/\s*;/', $part_content_type)[0]);

            // Decode part body
            if (preg_match('/Content-Transfer-Encoding:\s*(\S+)/i', $part_headers, $enc_match)) {
                $part_encoding = strtolower(trim($enc_match[1]));
                if ($part_encoding === 'base64') {
                    $part_body = base64_decode($part_body);
                } elseif ($part_encoding === 'quoted-printable') {
                    $part_body = quoted_printable_decode($part_body);
                }
            }

            $filename = '';
            if (preg_match('/filename\*?=\s*([^;\r\n]+)/i', $part_disposition, $filename_match)) {
                $filename = decodeAttachmentFilename($filename_match[1]);
            } elseif (preg_match('/name\*?=\s*([^;\r\n]+)/i', $part_content_type, $name_match)) {
                $filename = decodeAttachmentFilename($name_match[1]);
            }

            $is_attachment = !empty($filename) || stripos($part_disposition, 'attachment') !== false;

            if ($is_attachment) {
                $attachments[] = [
                    'filename' => $filename ?: 'attachment-' . (count($attachments) + 1),
                    'content_type' => $part_type ?: 'application/octet-stream',
                    'content' => $part_body,
                    'size' => strlen($part_body),
                ];
                continue;
            }
            
            if (stripos($part_type, 'text/plain') !== false) {
                $body_text = $part_body;
            } elseif (stripos($part_type, 'text/html') !== false) {
                $body_html = $part_body;
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

$attachment_index = isset($_GET['attachment']) ? intval($_GET['attachment']) : null;
if ($attachment_index !== null && $attachment_index >= 0) {
    if (!isset($attachments[$attachment_index])) {
        die(__('msg_not_found'));
    }
    $attachment = $attachments[$attachment_index];
    $safe_filename = str_replace(["\r", "\n", '"'], '', $attachment['filename']);
    $safe_filename = $safe_filename ?: 'attachment-' . $attachment_index;
    $content_type = $attachment['content_type'] ?: 'application/octet-stream';

    header('Content-Type: ' . $content_type);
    header('Content-Length: ' . $attachment['size']);
    header(
        'Content-Disposition: attachment; filename="' . $safe_filename . '"; filename*=UTF-8\'\'' . rawurlencode($safe_filename)
    );
    echo $attachment['content'];
    exit;
}

// Get trace log
$stmt = $db->prepare("
    SELECT * FROM trace_log 
    WHERE quarantine_id = ? 
    ORDER BY timestamp DESC
");
$stmt->execute([$id]);
$trace_logs = $stmt->fetchAll();

// Parse Rspamd symbols (symbol + score only)
$parsed_symbols = [];
if (!empty($message['symbols'])) {
    // Robust regex for Rspamd JSON format
    if (preg_match_all('/"name":"([^"]+)".*?"score":([+-]?\d+(?:\.\d+)?)/s', $message['symbols'], $matches, PREG_SET_ORDER)) {
        foreach ($matches as $match) {
            $name = trim($match[1]);
            $score = floatval($match[2]);
            if ($name) {  // Skip empty names
                $parsed_symbols[] = ['name' => $name, 'score' => $score];
            }
        }
    }
}
// Sort by score descending
usort($parsed_symbols, function($a, $b) {
    return $b['score'] <=> $a['score'];
});

$from_header_clean = trim($from_header);
$to_header_clean = trim($to_header);
$sender_clean = trim($message['sender'] ?? '');
$recipient_clean = trim($message['recipients'] ?? '');
$show_from_header = !empty($from_header_clean) && strcasecmp($from_header_clean, $sender_clean) !== 0;
$show_to_header = !empty($to_header_clean) && strcasecmp($to_header_clean, $recipient_clean) !== 0;

$dkim_dmarc_symbols = array_values(array_filter($parsed_symbols, function($sym) {
    return stripos($sym['name'], 'dkim') !== false || stripos($sym['name'], 'dmarc') !== false;
}));
$dkim_present = !empty($dkim_header);
$dmarc_present = !empty($dmarc_header) || array_filter($dkim_dmarc_symbols, fn($sym) => stripos($sym['name'], 'dmarc') !== false);
$dkim_status = $dkim_present ? __('yes') : __('no');
$dmarc_status = $dmarc_present ? __('yes') : __('no');

$released = !empty($message['released']);
$released_by = $message['released_by'] ?? '';
$released_at = $message['released_at'] ?? '';

$action = $message['action'] ?? 'unknown';
$actionClass = 'badge badge-pass';
$actionIcon = 'fa-check-circle';
$actionLabel = $action;

switch (strtolower($action)) {
    case 'reject':
        $actionClass = 'badge badge-reject';
        $actionIcon = 'fa-ban';
        $actionLabel = __('action_reject');
        break;
    case 'no action':
    case 'pass':
        $actionClass = 'badge badge-pass';
        $actionIcon = 'fa-check-circle';
        $actionLabel = __('action_no_action');
        break;
    case 'add header':
        $actionClass = 'badge badge-header';
        $actionIcon = 'fa-tag';
        $actionLabel = __('action_add_header');
        break;
    case 'greylist':
        $actionClass = 'badge badge-pass';
        $actionIcon = 'fa-clock';
        $actionLabel = __('action_greylist');
        break;
    case 'soft reject':
    case 'soft_reject':
        $actionClass = 'badge badge-soft-reject';
        $actionIcon = 'fa-exclamation-triangle';
        $actionLabel = __('action_soft_reject');
        break;
    default:
        $actionClass = 'badge badge-pass';
        $actionIcon = 'fa-question-circle';
}

?>
<!DOCTYPE html>
<html lang="<?= htmlspecialchars(currentLang()) ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars(__('view_page_title', ['app' => __('app_title')])) ?></title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <link rel="stylesheet" href="css/style.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #eef2f5; }
        .modal-overlay { min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 28px; }
        .modal-window { width: min(1300px, 96vw); max-height: 90vh; background: #fff; border-radius: 10px; box-shadow: 0 24px 60px rgba(15, 23, 42, 0.2); border: 1px solid #e2e8f0; display: flex; flex-direction: column; overflow: hidden; }
        .modal-header { display: flex; align-items: center; justify-content: space-between; padding: 12px 18px; background: #f8fafc; border-bottom: 1px solid #e2e8f0; }
        .modal-header .title { display: flex; align-items: center; gap: 10px; font-size: 15px; font-weight: 600; color: #1f2937; }
        .modal-header .meta { font-size: 11px; color: #6b7280; margin-top: 4px; }
        .modal-close { color: #6b7280; text-decoration: none; font-size: 18px; padding: 4px 8px; border-radius: 6px; }
        .modal-close:hover { background: #e2e8f0; color: #111827; }
        .modal-content { display: flex; min-height: 0; }
        .info-panel { width: 38%; border-right: 1px solid #e2e8f0; padding: 16px; overflow: auto; }
        .message-panel { flex: 1; padding: 16px; display: flex; flex-direction: column; gap: 12px; min-width: 0; }
        .panel-title { font-size: 14px; font-weight: 600; color: #1f2937; padding-bottom: 8px; border-bottom: 2px solid #3498db; margin-bottom: 12px; display: flex; align-items: center; gap: 8px; }
        table.info-table { width: 100%; border-collapse: collapse; font-size: 12px; }
        table.info-table th { text-transform: uppercase; font-size: 10px; letter-spacing: 0.4px; color: #6b7280; padding: 8px 6px; text-align: left; width: 160px; vertical-align: top; }
        table.info-table td { padding: 8px 6px; border-bottom: 1px solid #eef2f5; color: #1f2937; }
        table.info-table strong { color: #111827; }
        .symbol-inline { display: inline-flex; flex-wrap: wrap; gap: 6px; margin-left: 6px; }
        .symbol-badge { background: #e11d48; color: #fff; padding: 2px 6px; border-radius: 4px; font-size: 10px; font-family: monospace; }
        .action-badge { display: inline-flex; align-items: center; gap: 6px; }
        .badge { display: inline-flex; align-items: center; justify-content: center; padding: 2px 6px; border-radius: 6px; font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.3px; line-height: 1.3; white-space: nowrap; box-shadow: 0 1px 4px rgba(0,0,0,0.12); border: 1px solid rgba(0,0,0,0.1); gap: 6px; }
        .badge-reject { background: #c82333; color: #ffffff; box-shadow: 0 4px 12px rgba(200,35,51,0.4); }
        .badge-soft-reject { background: #17a2b8; color: #ffffff; box-shadow: 0 4px 12px rgba(23,162,184,0.4); }
        .badge-pass { background: #009933; color: #ffffff; box-shadow: 0 4px 12px rgba(51, 204, 0, 1); }
        .badge-header { color: #000; background-color: rgba(255,193,7,1); box-shadow: 0 4px 12px rgba(255,193,7,0.5); }
        .tabs { display: flex; gap: 8px; border-bottom: 1px solid #e2e8f0; flex-wrap: wrap; }
        .tab { padding: 8px 14px; background: #f1f5f9; border: none; cursor: pointer; border-radius: 6px 6px 0 0; font-size: 12px; color: #1f2937; }
        .tab.active { background: #3498db; color: #fff; }
        .tab-content { display: none; flex: 1; min-height: 0; }
        .tab-content.active { display: block; }
        .body-viewer { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 12px; height: 100%; max-height: 100%; overflow: auto; }
        .body-viewer pre { white-space: pre-wrap; word-wrap: break-word; font-family: 'Courier New', monospace; font-size: 12px; color: #1f2937; }
        .body-viewer iframe { width: 100%; min-height: 420px; border: none; background: #fff; }
        .raw-headers { background: #0f172a; color: #e2e8f0; padding: 12px; border-radius: 6px; font-family: 'Courier New', monospace; font-size: 11px; overflow-x: auto; }
        @media (max-width: 1100px) {
            .modal-content { flex-direction: column; }
            .info-panel { width: 100%; border-right: none; border-bottom: 1px solid #e2e8f0; }
        }
    </style>
</head>
<body>
    <div class="modal-overlay">
        <div class="modal-window" role="dialog" aria-modal="true" aria-label="<?= htmlspecialchars(__('view_title')) ?>">
            <div class="modal-header">
                <div>
                    <div class="title">
                        <i class="fas fa-envelope-open-text"></i>
                        <?= htmlspecialchars(__('view_title')) ?>
                    </div>
                    <div class="meta">
                        <?= htmlspecialchars(__('view_message_id_label')) ?>: <?= htmlspecialchars($message['message_id'] ?? __('view_message_id_na')) ?>
                        · <?= date('d.m.Y H:i:s', strtotime($message['timestamp'])) ?>
                    </div>
                </div>
                <a class="modal-close" href="index.php" aria-label="<?= htmlspecialchars(__('close')) ?>">
                    <i class="fas fa-times"></i>
                </a>
            </div>
            <div class="modal-content">
                <section class="info-panel">
                    <h2 class="panel-title"><i class="fas fa-info-circle"></i> <?= htmlspecialchars(__('view_basic_info')) ?></h2>
                    <table class="info-table">
                        <tr>
                            <th><?= htmlspecialchars(__('msg_subject')) ?>:</th>
                            <td><strong><?= htmlspecialchars($subject_decoded) ?></strong></td>
                        </tr>
                        <tr>
                            <th><?= htmlspecialchars(__('msg_sender')) ?>:</th>
                            <td><?= htmlspecialchars($from_decoded) ?></td>
                        </tr>
                        <?php if ($show_from_header): ?>
                        <tr>
                            <th><?= htmlspecialchars(__('view_from_header')) ?>:</th>
                            <td><?= htmlspecialchars($from_header) ?></td>
                        </tr>
                        <?php endif; ?>
                        <tr>
                            <th><?= htmlspecialchars(__('msg_recipient')) ?>:</th>
                            <td><strong><?= htmlspecialchars($to_decoded) ?></strong></td>
                        </tr>
                        <?php if ($show_to_header): ?>
                        <tr>
                            <th><?= htmlspecialchars(__('view_to_header')) ?>:</th>
                            <td><?= htmlspecialchars($to_header) ?></td>
                        </tr>
                        <?php endif; ?>
                        <tr>
                            <th><?= htmlspecialchars(__('view_dkim_dmarc')) ?>:</th>
                            <td>
                                <?= htmlspecialchars(__('view_dkim_label')) ?>: <strong><?= htmlspecialchars($dkim_status) ?></strong>
                                · <?= htmlspecialchars(__('view_dmarc_label')) ?>: <strong><?= htmlspecialchars($dmarc_status) ?></strong>
                                <?php if (!empty($dkim_dmarc_symbols)): ?>
                                    <span class="symbol-inline">
                                        <?php foreach ($dkim_dmarc_symbols as $sym): ?>
                                            <span class="symbol-badge"><?= htmlspecialchars($sym['name']) ?></span>
                                        <?php endforeach; ?>
                                    </span>
                                <?php endif; ?>
                            </td>
                        </tr>
                        <?php if (!empty($spam_header)): ?>
                        <tr>
                            <th><?= htmlspecialchars(__('view_spam_header')) ?>:</th>
                            <td><?= htmlspecialchars($spam_header) ?></td>
                        </tr>
                        <?php endif; ?>
                        <?php if (!empty($user_agent_header)): ?>
                        <tr>
                            <th><?= htmlspecialchars(__('view_user_agent')) ?>:</th>
                            <td><?= htmlspecialchars($user_agent_header) ?></td>
                        </tr>
                        <?php endif; ?>
                        <tr>
                            <th><?= htmlspecialchars(__('ip_address')) ?>:</th>
                            <td><?= htmlspecialchars($message['ip_address']) ?></td>
                        </tr>
                        <?php if (!empty($message['authenticated_user'])): ?>
                        <tr>
                            <th><?= htmlspecialchars(__('view_authenticated_user')) ?>:</th>
                            <td><?= htmlspecialchars($message['authenticated_user']) ?></td>
                        </tr>
                        <?php endif; ?>
                        <tr>
                            <th><?= htmlspecialchars(__('msg_action')) ?>:</th>
                            <td>
                                <span class="action-badge <?= $actionClass; ?>">
                                    <i class="fas <?= $actionIcon; ?>"></i>
                                    <?= htmlspecialchars($actionLabel) ?>
                                </span>
                            </td>
                        </tr>
                        <tr>
                            <th><?= htmlspecialchars(__('msg_score')) ?>:</th>
                            <td><strong style="color: <?= $message['score'] >= 15 ? '#e74c3c' : ($message['score'] >= 6 ? '#f39c12' : '#27ae60') ?>;"><?= number_format($message['score'], 2) ?></strong></td>
                        </tr>
                        <tr>
                            <th><?= htmlspecialchars(__('status')) ?>:</th>
                            <td>
                                <?php if ($released): ?>
                                    <span class="timeline-action"><?= htmlspecialchars(__('view_status_released')) ?></span>
                                    <?= htmlspecialchars($released_by) ?>
                                    (<?= date('d.m.Y H:i', strtotime($released_at)) ?>)
                                <?php else: ?>
                                    <span class="timeline-action"><?= htmlspecialchars(__('view_status_quarantined')) ?></span>
                                <?php endif; ?>
                            </td>
                        </tr>
                    </table>
                </section>
                <section class="message-panel">
                    <h2 class="panel-title"><i class="fas fa-file-alt"></i> <?= htmlspecialchars(__('msg_body')) ?></h2>
                    <div class="tabs">
                        <?php if (!empty($body_html)): ?>
                            <button class="tab active" onclick="showTab('html', event)"><?= htmlspecialchars(__('view_html_preview_safe')) ?></button>
                        <?php endif; ?>
                        <?php if (!empty($body_text)): ?>
                            <button class="tab <?= empty($body_html) ? 'active' : '' ?>" onclick="showTab('text', event)"><?= htmlspecialchars(__('view_text_tab')) ?></button>
                        <?php endif; ?>
                        <button class="tab" onclick="showTab('source', event)"><?= htmlspecialchars(__('view_source_tab')) ?></button>
                        <button class="tab" onclick="showTab('headers', event)"><?= htmlspecialchars(__('msg_headers')) ?></button>
                    </div>

                    <?php if (!empty($body_html)): ?>
                    <div id="tab-html" class="tab-content active">
                        <div class="body-viewer">
                            <iframe id="html-frame" sandbox=""></iframe>
                        </div>
                        <script>
                            const htmlContent = <?= json_encode($body_html) ?>;
                            const iframe = document.getElementById('html-frame');
                            iframe.srcdoc = htmlContent;
                        </script>
                    </div>
                    <?php endif; ?>

                    <?php if (!empty($body_text)): ?>
                    <div id="tab-text" class="tab-content <?= empty($body_html) ? 'active' : '' ?>">
                        <div class="body-viewer">
                            <pre><?= htmlspecialchars($body_text) ?></pre>
                        </div>
                    </div>
                    <?php endif; ?>

                    <div id="tab-source" class="tab-content">
                        <div class="body-viewer">
                            <pre><?= htmlspecialchars($message['message_content']) ?></pre>
                        </div>
                    </div>

                    <div id="tab-headers" class="tab-content">
                        <div class="raw-headers">
                            <?= htmlspecialchars($headers_raw) ?>
                        </div>
                    </div>
                </section>
            </div>
        </div>
    </div>
    <script>
        function showTab(tabName, event) {
            if (event) {
                event.preventDefault();
            }
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });
            document.querySelectorAll('.tab').forEach(tab => {
                tab.classList.remove('active');
            });

            const activeTab = document.getElementById('tab-' + tabName);
            if (activeTab) {
                activeTab.classList.add('active');
            }
            if (event && event.target) {
                event.target.classList.add('active');
            }
        }
    </script>
</body>
</html>
