<?php
/*
 * Version: 2.0.0
 * Author: Martin Pouzar
 * License: GNU General Public License v3.0
 */
// operations.php - Zpracování operací s karanténními zprávami
// Upraveno pro podporu volání z process_bulk.php bez redirectu


require_once __DIR__ . '/config.php';
requireAuth();

// Determine return URL
$returnUrl = $_POST['return_url'] ?? ($_SERVER['HTTP_REFERER'] ?? 'index.php');

if (!checkPermission('domain_admin')) {
    $_SESSION['error_msg'] = 'Nemáte oprávnění k hromadným operacím';
    header('Location: index.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: ' . $returnUrl);
    exit;
}

// Detekce, zda jsme voláni z process_bulk.php (bez redirectu)
$is_bulk_mode = defined('BULK_PROCESSING_MODE') && BULK_PROCESSING_MODE === true;

/**
 * Learn message via Rspamd API
 */
if (!function_exists('learnMessage')) {
    function learnMessage($message_content, $type = 'spam') {
        if (!defined('RSPAMD_API_URL') || empty(RSPAMD_API_URL)) {
            return ['success' => false, 'error' => 'Rspamd API není nakonfigurováno'];
        }

        $rspamd_url = RSPAMD_API_URL . '/learn' . ($type === 'spam' ? 'spam' : 'ham');

        $ch = curl_init($rspamd_url);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $message_content);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);

        $headers = ['Content-Type: text/plain'];
        if (defined('RSPAMD_API_PASSWORD') && !empty(RSPAMD_API_PASSWORD)) {
            $headers[] = 'Password: ' . RSPAMD_API_PASSWORD;
        }

        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        $response = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($http_code >= 200 && $http_code < 300) {
            return ['success' => true];
        }

        return ['success' => false, 'error' => 'HTTP ' . $http_code];
    }
}
/**
 * Safely release message via sendmail
 */
if (!function_exists('safeSendmailRelease')) {
    function safeSendmailRelease($db, $id, $user) {
        $stmt = $db->prepare("SELECT message_content, sender, recipients FROM quarantine_messages WHERE id = ? AND state = 0");
        $stmt->execute([$id]);
        $msg = $stmt->fetch();

        if (!$msg) return false;

        // Validace emailů
        if (!filter_var($msg['sender'], FILTER_VALIDATE_EMAIL) || empty($msg['recipients'])) {
            error_log("Invalid sender/recipient for ID $id");
            return false;
        }

        // Označ released
        $update_stmt = $db->prepare("UPDATE quarantine_messages SET state = 3, state_at=NOW(), state_by=? WHERE id=?");

        // Sendmail
        $tmp_file = tempnam(sys_get_temp_dir(), 'release_');
        file_put_contents($tmp_file, $msg['message_content']);

        $recipients_clean = preg_replace('/[^a-zA-Z0-9@._-]/', '', $msg['recipients']);
        $command = "/usr/sbin/sendmail -t -f " . escapeshellarg($msg['sender']) . " " . escapeshellarg($recipients_clean);

        $result_code = 0;
        exec($command . " < $tmp_file 2>&1", $output, $result_code);
        unlink($tmp_file);

        if ($result_code !== 0) {
            error_log("Sendmail failed ID $id: " . implode("\n", $output));
            return false;
        }

        $update_stmt->execute([$user, $id]);
        return true;
    }
}

// Main execution
$db = Database::getInstance()->getConnection();
$user = $_SESSION['username'] ?? 'unknown';
$user_id = $_SESSION['user_id'] ?? null;

$operation = $_POST['operation'] ?? '';
$message_ids_str = $_POST['message_ids'] ?? '';

if (empty($operation) || empty($message_ids_str)) {
    $_SESSION['error_msg'] = 'Neplatná operace';
    if (!$is_bulk_mode) {
        header('Location: ' . $returnUrl);
        exit;
    }
    return;
}

// Parse message IDs
$message_ids = array_map('intval', explode(',', $message_ids_str));
$message_ids = array_filter($message_ids, function($id) { return $id > 0; });

if (empty($message_ids)) {
    $_SESSION['error_msg'] = 'Žádné zprávy k zpracování';
    if (!$is_bulk_mode) {
        header('Location: ' . $returnUrl);
        exit;
    }
    return;
}

// Check domain access for all messages
$placeholders = implode(',', array_fill(0, count($message_ids), '?'));
$check_sql = "SELECT id, sender, recipients, subject, message_content FROM quarantine_messages WHERE id IN ($placeholders)";
$check_stmt = $db->prepare($check_sql);
$check_stmt->execute($message_ids);
$messages = $check_stmt->fetchAll();

$message_lookup = [];
foreach ($messages as $msg) {
    $message_lookup[$msg['id']] = $msg;
}

$buildAuditDetails = function (string $base, ?array $msg): string {
    if (!$msg) {
        return $base;
    }

    $subject = decodeMimeHeader($msg['subject'] ?? '');
    $from = $msg['sender'] ?? '';
    $details = [];

    if ($from !== '') {
        $details[] = "from: $from";
    }
    if ($subject !== '') {
        $details[] = "subject: $subject";
    }

    if (empty($details)) {
        return $base;
    }

    return $base . ' (' . implode(', ', $details) . ')';
};

if ($_SESSION['user_role'] !== 'admin') {
    foreach ($messages as $msg) {
        if (!checkDomainAccess($msg['sender']) && !checkDomainAccess($msg['recipients'])) {
            $_SESSION['error_msg'] = 'Nemáte oprávnění k některým zprávám';
            if (!$is_bulk_mode) {
                header('Location: ' . $returnUrl);
                exit;
            }
            return;
        }
    }
}

$success_count = 0;
$error_count = 0;

try {
    $db->beginTransaction();

    switch ($operation) {
        case 'forget':
            // Reset learning nebo smazání ze statistik
            $stmt = $db->prepare("DELETE FROM trace_log WHERE id = ? AND action IN ('learned_spam', 'learned_ham')");
            foreach ($message_ids as $id) {
                $stmt->execute([$id]);
                $success_count++;
            }

            $db->commit();
            $_SESSION['success_msg'] = "Zapomenuto $success_count zpráv";
            break;

        case 'release':
            foreach ($message_ids as $id) {
                if (safeSendmailRelease($db, (int)$id, $_SESSION['username'])) {
                    $success_count++;
                }
            }

            $db->commit();
            $_SESSION['success_msg'] = "$success_count z " . count($message_ids) . " zpráv uvolněno/odesláno sendmailem";
            break;

        case 'delete':
            $stmt = $db->prepare("DELETE FROM quarantine_messages WHERE id = ?");
            foreach ($message_ids as $id) {
                try {
                    $stmt->execute([$id]);
                    $success_count++;
                    $msg = $message_lookup[$id] ?? null;
                    $details = $buildAuditDetails("Bulk deleted message ID $id", $msg);
                    logAudit($user_id, $user, 'bulk_delete', 'quarantine', $id, $details);
                } catch (Exception $e) {
                    $error_count++;
                    error_log("Bulk delete error for ID $id: " . $e->getMessage());
                }
            }

            $db->commit();
            $_SESSION['success_msg'] = "Smazáno $success_count " . ($success_count === 1 ? 'zpráva' : ($success_count < 5 ? 'zprávy' : 'zpráv'));
            if ($error_count > 0) {
                $_SESSION['error_msg'] = "Chyba při mazání $error_count " . ($error_count === 1 ? 'zprávy' : 'zpráv');
            }
            break;

        case 'learn_ham':
            $log_stmt = $db->prepare("INSERT INTO trace_log (quarantine_id, action, user, details) VALUES (?, 'learned_ham', ?, 'Bulk learned as HAM')");
            $update_stmt = $db->prepare("UPDATE quarantine_messages SET state = 1, state_at=NOW(), state_by=? WHERE id=?");

            foreach ($messages as $msg) {
                try {
                    $result = learnMessage($msg['message_content'], 'ham');
                    if ($result['success']) {
                        $log_stmt->execute([$msg['id'], $user]);
                        $update_stmt->execute([$user, $msg['id']]);
                        $success_count++;
                        $details = $buildAuditDetails("Bulk learned as HAM ID " . $msg['id'], $msg);
                        logAudit($user_id, $user, 'bulk_learn_ham', 'quarantine', $msg['id'], $details);
                    } else {
                        $error_count++;
                        error_log("Learn HAM error for ID {$msg['id']}: " . ($result['error'] ?? 'Unknown'));
                    }
                } catch (Exception $e) {
                    $error_count++;
                    error_log("Learn HAM exception for ID {$msg['id']}: " . $e->getMessage());
                }
            }

            $db->commit();
            $_SESSION['success_msg'] = "Naučeno jako HAM: $success_count " . ($success_count === 1 ? 'zpráva' : ($success_count < 5 ? 'zprávy' : 'zpráv'));
            if ($error_count > 0) {
                $_SESSION['warning_msg'] = "Chyba při učení $error_count " . ($error_count === 1 ? 'zprávy' : 'zpráv');
            }
            break;

        case 'learn_spam':
            $log_stmt = $db->prepare("INSERT INTO trace_log (quarantine_id, action, user, details) VALUES (?, 'learned_spam', ?, 'Bulk learned as SPAM')");
            $update_stmt = $db->prepare("UPDATE quarantine_messages SET state = 2, state_at=NOW(), state_by=? WHERE id=?");

            foreach ($messages as $msg) {
                try {
                    $result = learnMessage($msg['message_content'], 'spam');
                    if ($result['success']) {
                        $log_stmt->execute([$msg['id'], $user]);
                        $update_stmt->execute([$user, $msg['id']]);
                        $success_count++;
                        $details = $buildAuditDetails("Bulk learned as SPAM ID " . $msg['id'], $msg);
                        logAudit($user_id, $user, 'bulk_learn_spam', 'quarantine', $msg['id'], $details);
                    } else {
                        $error_count++;
                        error_log("Learn SPAM error for ID {$msg['id']}: " . ($result['error'] ?? 'Unknown'));
                    }
                } catch (Exception $e) {
                    $error_count++;
                    error_log("Learn SPAM exception for ID {$msg['id']}: " . $e->getMessage());
                }
            }

            $db->commit();
            $_SESSION['success_msg'] = "Naučeno jako SPAM: $success_count " . ($success_count === 1 ? 'zpráva' : ($success_count < 5 ? 'zprávy' : 'zpráv'));
            if ($error_count > 0) {
                $_SESSION['warning_msg'] = "Chyba při učení $error_count " . ($error_count === 1 ? 'zprávy' : 'zpráv');
            }
            break;

        default:
            $db->rollBack();
            $_SESSION['error_msg'] = 'Neznámá operace';
    }

} catch (Exception $e) {
    $db->rollBack();
    error_log("Bulk operation error: " . $e->getMessage());
    $_SESSION['error_msg'] = 'Chyba při zpracování: ' . $e->getMessage();
}

// Redirect pouze pokud nejsme v bulk módu
if (!$is_bulk_mode) {
    header('Location: ' . $returnUrl);
    exit;
}
?>