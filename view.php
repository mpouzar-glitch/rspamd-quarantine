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
            
            // Parse part content type
            if (preg_match('/Content-Type:\s*([^\r\n;]+)/i', $part_headers, $ct_match)) {
                $part_type = trim($ct_match[1]);
                
                // Decode part body
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
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        .header { background: #2c3e50; color: white; padding: 20px; margin: -20px -20px 20px -20px; }
        .header h1 { font-size: 24px; margin-bottom: 10px; }
        .header .back { color: white; text-decoration: none; display: inline-block; margin-bottom: 10px; }
        .header .back:hover { text-decoration: underline; }
        .card { background: white; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .card h2 { color: #2c3e50; margin-bottom: 15px; font-size: 18px; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
        .info-grid { display: flex; gap: 20px; align-items: stretch; }
        .info-block { flex: 1; min-width: 0; display: flex; flex-direction: column; }
        table.info-table { width: 100%; border-collapse: collapse; font-size: 13px; }
        table.info-table th { background: #ecf0f1; padding: 12px; text-align: left; width: 200px; font-weight: 600; color: #2c3e50; }
        table.info-table td { padding: 12px; border-bottom: 1px solid #ecf0f1; }
        .headers-panel { background: #f8f9fa; border: 1px solid #ddd; border-radius: 4px; padding: 12px; font-family: 'Courier New', monospace; font-size: 10px; line-height: 1.4; overflow: auto; flex: 1; }
        .headers-panel h3 { font-size: 13px; margin-bottom: 8px; color: #2c3e50; }
        .headers-panel pre { margin: 0; white-space: pre-wrap; word-break: break-word; }
        @media (max-width: 1000px) { .info-grid { flex-direction: column; } }
        .symbols { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 5px; }
        .symbol-badge { background: #e74c3c; color: white; padding: 4px 8px; border-radius: 3px; font-size: 11px; font-family: monospace; }
        .symbol-badge.low { background: #95a5a6; }
        .symbol-inline { display: inline-flex; flex-wrap: wrap; gap: 6px; margin-left: 8px; }
        .symbol-inline .symbol-badge { font-size: 10px; padding: 3px 6px; }
        .body-viewer { background: #f8f9fa; border: 1px solid #ddd; border-radius: 4px; padding: 15px; max-height: 600px; overflow-y: auto; }
        .body-viewer pre { white-space: pre-wrap; word-wrap: break-word; font-family: 'Courier New', monospace; font-size: 12px; }
        .body-viewer iframe { width: 100%; min-height: 500px; border: none; background: white; }
        .tabs { display: flex; gap: 10px; margin-bottom: 15px; border-bottom: 2px solid #ecf0f1; }
        .tab { padding: 10px 20px; background: #ecf0f1; border: none; cursor: pointer; border-radius: 4px 4px 0 0; font-size: 14px; }
        .tab.active { background: #3498db; color: white; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .badge { display: inline-flex; align-items: center; justify-content: center; padding: 2px 6px; border-radius: 6px; font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.3px; line-height: 1.3; white-space: nowrap; box-shadow: 0 1px 4px rgba(0,0,0,0.15); border: 1px solid rgba(0,0,0,0.1); gap: 6px; }
        .badge-reject { background: #c82333; color: #ffffff; box-shadow: 0 4px 12px rgba(200,35,51,0.4); }
        .badge-soft-reject { background: #17a2b8; color: #ffffff; box-shadow: 0 4px 12px rgba(23,162,184,0.4); }
        .badge-pass { background: #009933; color: #ffffff; box-shadow: 0 4px 12px rgba(51, 204, 0, 1); }
        .badge-header { color: #000; background-color: rgba(255,193,7,1); box-shadow: 0 4px 12px rgba(255,193,7,0.5); }
        .badge-released { background: #27ae60; color: white; }
        .badge-quarantine { background: #e67e22; color: white; }
        .action-badge { display: inline-flex; align-items: center; gap: 6px; }
        .actions { display: flex; gap: 10px; margin-top: 20px; }
        .btn { padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; font-size: 14px; }
        .btn i { margin-right: 5px; }
        .btn-primary { background: #3498db; color: white; }
        .btn-success { background: #27ae60; color: white; }
        .btn-warning { background: #f39c12; color: white; }
        .btn-danger { background: #e74c3c; color: white; }
        .btn:hover { opacity: 0.9; }
        .raw-headers { background: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 11px; overflow-x: auto; }
        .timeline { position: relative; padding-left: 30px; }
        .timeline-item { position: relative; padding-bottom: 20px; }
        .timeline-item:before { content: ''; position: absolute; left: -24px; top: 5px; width: 12px; height: 12px; border-radius: 50%; background: #3498db; border: 2px solid white; }
        .timeline-item:after { content: ''; position: absolute; left: -19px; top: 17px; width: 2px; height: calc(100% - 12px); background: #ddd; }
        .timeline-item:last-child:after { display: none; }
        .timeline-time { font-size: 11px; color: #7f8c8d; }
        .timeline-action { font-weight: bold; color: #2c3e50; }
        .timeline-user { color: #3498db; font-size: 12px; }
        .symbols { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; max-height: 120px; overflow-x: auto;
            padding: 8px;
            background: #f8f9fa;
            border-radius: 4px;
        }
        .symbol-badge {
            background: #e74c3c;
            color: white;
            padding: 6px 10px;
            border-radius: 4px;
            font-size: 12px;
            font-family: monospace;
            white-space: nowrap;
            font-weight: 500;
        }

    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <a href="index.php" class="back"><i class="fas fa-arrow-left"></i> <?= htmlspecialchars(__('view_back_to_list')) ?></a>
            <h1><i class="fas fa-envelope-open-text"></i> <?= htmlspecialchars(__('view_title')) ?></h1>
            <div style="font-size: 14px; opacity: 0.9; margin-top: 5px;">
                <?= htmlspecialchars(__('view_message_id_label')) ?>: <?= htmlspecialchars($message['message_id'] ?? __('view_message_id_na')) ?>
            </div>
        </div>
        
        <div class="card">
            <h2><i class="fas fa-info-circle"></i> <?= htmlspecialchars(__('view_basic_info')) ?></h2>
            <div class="info-grid">
                <div class="info-block">
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
                                <?= htmlspecialchars(__('view_dkim_label')) ?>: <strong><?= htmlspecialchars($dkim_status) ?></strong> · <?= htmlspecialchars(__('view_dmarc_label')) ?>: <strong><?= htmlspecialchars($dmarc_status) ?></strong>
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
                            <th><?= htmlspecialchars(__('msg_date')) ?>:</th>
                            <td><?= date('d.m.Y H:i:s', strtotime($message['timestamp'])) ?></td>
                        </tr>
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
                </div>
                <div class="info-block">
                    <div class="headers-panel">
                        <h3><?= htmlspecialchars(__('view_message_headers')) ?></h3>
                        <pre><?= htmlspecialchars($headers_raw) ?></pre>
                    </div>
                </div>
            </div>
        </div>
        
        <?php if (!empty($parsed_symbols)): ?>
        <div class="card">
            <h2><i class="fas fa-flag"></i> <?= htmlspecialchars(__('symbols_header', ['count' => count($parsed_symbols)])) ?></h2>
            <div class="symbols">
                <?php foreach ($parsed_symbols as $sym): 
                    $score = $sym['score'];
                    $bg_color = $score > 1 ? '#e74c3c' : ($score > 0 ? '#f39c12' : ($score < 0 ? '#27ae60' : '#95a5a6'));
                ?>
                    <span class="symbol-badge" style="background: <?= $bg_color ?>;">
                        <?= htmlspecialchars($sym['name']) ?>: <?= number_format($score, 1) ?>
                    </span>
                <?php endforeach; ?>
            </div>
        </div>
        <?php endif; ?>

        
        <div class="card">
            <h2><i class="fas fa-file-alt"></i> <?= htmlspecialchars(__('msg_body')) ?></h2>
            
            <div class="tabs">
                <?php if (!empty($body_html)): ?>
                    <button class="tab active" onclick="showTab('html')"><?= htmlspecialchars(__('view_html_preview_safe')) ?></button>
                <?php endif; ?>
                <?php if (!empty($body_text)): ?>
                    <button class="tab <?= empty($body_html) ? 'active' : '' ?>" onclick="showTab('text')"><?= htmlspecialchars(__('view_text_tab')) ?></button>
                <?php endif; ?>
                <button class="tab" onclick="showTab('source')"><?= htmlspecialchars(__('view_source_tab')) ?></button>
                <button class="tab" onclick="showTab('headers')"><?= htmlspecialchars(__('msg_headers')) ?></button>
            </div>
            
            <?php if (!empty($body_html)): ?>
            <div id="tab-html" class="tab-content active">
                <div class="body-viewer">
                    <iframe id="html-frame" sandbox=""></iframe>
                </div>
                <script>
                    // Safe HTML rendering inside a sandboxed iframe
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
        </div>
        
        <?php if (!empty($trace_logs)): ?>
        <div class="card">
            <h2><i class="fas fa-history"></i> <?= htmlspecialchars(__('view_action_history')) ?></h2>
            <div class="timeline">
                <?php foreach ($trace_logs as $log): ?>
                    <div class="timeline-item">
                        <div class="timeline-time"><?= date('d.m.Y H:i:s', strtotime($log['timestamp'])) ?></div>
                        <div class="timeline-action"><?= htmlspecialchars($log['action']) ?></div>
                        <div class="timeline-user"><?= htmlspecialchars(__('user')) ?>: <?= htmlspecialchars($log['user']) ?></div>
                        <?php if (!empty($log['details'])): ?>
                            <div style="font-size: 12px; color: #7f8c8d; margin-top: 5px;">
                                <?= htmlspecialchars($log['details']) ?>
                            </div>
                        <?php endif; ?>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>
        <?php endif; ?>
        
        <div class="card">
            <h2><i class="fas fa-tools"></i> <?= htmlspecialchars(__('actions')) ?></h2>
            <div class="actions">
                <?php if (!$released): ?>
                    <form method="post" action="index.php" onsubmit="return confirm('<?= htmlspecialchars(__('confirm_release'), ENT_QUOTES) ?>')">
                        <input type="hidden" name="id" value="<?= $message['id'] ?>">
                        <input type="hidden" name="action" value="release">
                        <button type="submit" class="btn btn-success">
                            <i class="fas fa-check"></i> <?= htmlspecialchars(__('msg_release')) ?>
                        </button>
                    </form>
                <?php endif; ?>
                
                <form method="post" action="index.php" onsubmit="return confirm('<?= htmlspecialchars(__('confirm_learn_ham'), ENT_QUOTES) ?>')">
                    <input type="hidden" name="id" value="<?= $message['id'] ?>">
                    <input type="hidden" name="action" value="learn_ham">
                    <button type="submit" class="btn btn-primary">
                        <i class="fas fa-thumbs-up"></i> <?= htmlspecialchars(__('msg_learn_ham')) ?>
                    </button>
                </form>
                
                <form method="post" action="index.php" onsubmit="return confirm('<?= htmlspecialchars(__('confirm_learn_spam'), ENT_QUOTES) ?>')">
                    <input type="hidden" name="id" value="<?= $message['id'] ?>">
                    <input type="hidden" name="action" value="learn_spam">
                    <button type="submit" class="btn btn-warning">
                        <i class="fas fa-thumbs-down"></i> <?= htmlspecialchars(__('msg_learn_spam')) ?>
                    </button>
                </form>
                
                <form method="post" action="index.php" onsubmit="return confirm('<?= htmlspecialchars(__('confirm_delete_message'), ENT_QUOTES) ?>')">
                    <input type="hidden" name="id" value="<?= $message['id'] ?>">
                    <input type="hidden" name="action" value="delete">
                    <button type="submit" class="btn btn-danger">
                        <i class="fas fa-trash"></i> <?= htmlspecialchars(__('msg_delete')) ?>
                    </button>
                </form>
                
                <a href="index.php" class="btn btn-primary">
                    <i class="fas fa-arrow-left"></i> <?= htmlspecialchars(__('view_back_to_list')) ?>
                </a>
            </div>
        </div>
    </div>
    
    <script>
        function showTab(tabName) {
            // Hide all tabs
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });
            document.querySelectorAll('.tab').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Show selected tab
            document.getElementById('tab-' + tabName).classList.add('active');
            event.target.classList.add('active');
        }
    </script>
</body>
</html>
