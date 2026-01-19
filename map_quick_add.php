<?php
/*
 * Version: 2.0.0
 * Author: Martin Pouzar
 * License: GNU General Public License v3.0
 */
/**
 * Quick add email address to whitelist/blacklist maps.
 */

session_start();
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/lang_helper.php';

requireAuth();

$returnUrl = $_POST['return_url'] ?? 'index.php';

if (!checkPermission('domain_admin')) {
    $_SESSION['error_msg'] = __('maps_permission_denied');
    header('Location: ' . $returnUrl);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: ' . $returnUrl);
    exit;
}

$action = $_POST['action'] ?? 'add';
$listType = $_POST['list_type'] ?? '';
$entryValue = trim($_POST['entry_value'] ?? '');
$entryType = $_POST['entry_type'] ?? 'email';

$allowedActions = ['add', 'delete'];
$allowedLists = ['whitelist', 'blacklist'];
$allowedEntryTypes = ['email', 'email_regex', 'subject'];

if (!in_array($action, $allowedActions, true)) {
    $_SESSION['error_msg'] = __('maps_invalid_input');
    header('Location: ' . $returnUrl);
    exit;
}

if (!in_array($listType, $allowedLists, true)) {
    $_SESSION['error_msg'] = __('maps_invalid_input');
    header('Location: ' . $returnUrl);
    exit;
}

if (!in_array($entryType, $allowedEntryTypes, true)) {
    $_SESSION['error_msg'] = __('maps_invalid_input');
    header('Location: ' . $returnUrl);
    exit;
}

if ($entryType === 'email' && (empty($entryValue) || !isValidMapEmailEntry($entryValue))) {
    $_SESSION['error_msg'] = __('maps_invalid_value');
    header('Location: ' . $returnUrl);
    exit;
}

if ($entryType === 'email_regex' && (empty($entryValue) || !isRegexMapEntry($entryValue))) {
    $_SESSION['error_msg'] = __('maps_invalid_value');
    header('Location: ' . $returnUrl);
    exit;
}

if ($entryType === 'subject' && (empty($entryValue) || !isRegexMapEntry($entryValue))) {
    $_SESSION['error_msg'] = __('maps_invalid_value');
    header('Location: ' . $returnUrl);
    exit;
}

if ($entryType === 'email' && !canManageEmailMapEntry($entryValue)) {
    $_SESSION['error_msg'] = __('maps_permission_denied');
    header('Location: ' . $returnUrl);
    exit;
}

if ($entryType === 'email_regex' && !canManageEmailMapEntry($entryValue)) {
    $_SESSION['error_msg'] = __('maps_permission_denied');
    header('Location: ' . $returnUrl);
    exit;
}

$db = Database::getInstance()->getConnection();
$user = $_SESSION['username'] ?? 'unknown';
$userId = $_SESSION['user_id'] ?? null;

if ($action === 'delete') {
    $entryStmt = $db->prepare("SELECT id FROM rspamd_map_entries WHERE list_type = ? AND entry_type = ? AND entry_value = ?");
    $entryStmt->execute([$listType, $entryType, $entryValue]);
    $entry = $entryStmt->fetch(PDO::FETCH_ASSOC);

    if (!$entry) {
        $_SESSION['error_msg'] = __('maps_not_found');
        header('Location: ' . $returnUrl);
        exit;
    }

    $deleteStmt = $db->prepare("DELETE FROM rspamd_map_entries WHERE id = ?");
    $deleteStmt->execute([$entry['id']]);
    $details = "Deleted {$listType} {$entryType}: {$entryValue}";
    logAudit($userId, $user, 'map_delete', 'rspamd_map_entry', $entry['id'], $details);
} else {
    $checkStmt = $db->prepare("SELECT COUNT(*) FROM rspamd_map_entries WHERE list_type = ? AND entry_type = ? AND entry_value = ?");
    $checkStmt->execute([$listType, $entryType, $entryValue]);
    if ($checkStmt->fetchColumn() > 0) {
        $_SESSION['error_msg'] = __('maps_duplicate');
        header('Location: ' . $returnUrl);
        exit;
    }

    $insertStmt = $db->prepare("INSERT INTO rspamd_map_entries (list_type, entry_type, entry_value, created_by, created_at, updated_at)
        VALUES (?, ?, ?, ?, NOW(), NOW())");
    $insertStmt->execute([$listType, $entryType, $entryValue, $user]);
    $entryId = $db->lastInsertId();
    $details = "Added {$listType} {$entryType}: {$entryValue}";
    logAudit($userId, $user, 'map_add', 'rspamd_map_entry', $entryId, $details);
}

$mapName = getRspamdMapName($listType, $entryType);
if (!$mapName) {
    $_SESSION['error_msg'] = __('maps_config_missing');
    header('Location: ' . $returnUrl);
    exit;
}

$stmt = $db->prepare("SELECT entry_value FROM rspamd_map_entries WHERE list_type = ? AND entry_type = ? ORDER BY entry_value ASC");
$stmt->execute([$listType, $entryType]);
$entries = $stmt->fetchAll(PDO::FETCH_ASSOC);
$content = buildRspamdMapContent($entries);

$upload = uploadRspamdMap($mapName, $content);

if (!$upload['success']) {
    $errors = [];
    foreach ($upload['results'] as $result) {
        if ($result['http_code'] < 200 || $result['http_code'] >= 300 || !empty($result['error'])) {
            $errors[] = $result['server'] . ' (HTTP ' . ($result['http_code'] ?: 'n/a') . ')';
        }
    }

    $_SESSION['error_msg'] = empty($errors)
        ? __('maps_upload_failed_generic')
        : __('maps_upload_failed', ['servers' => implode(', ', $errors)]);
    header('Location: ' . $returnUrl);
    exit;
}

$_SESSION['success_msg'] = $action === 'delete' ? __('maps_deleted') : __('maps_added');
header('Location: ' . $returnUrl);
exit;
