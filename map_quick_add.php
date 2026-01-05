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

$listType = $_POST['list_type'] ?? '';
$entryValue = trim($_POST['entry_value'] ?? '');
$entryType = 'email';

$allowedLists = ['whitelist', 'blacklist'];

if (!in_array($listType, $allowedLists, true)) {
    $_SESSION['error_msg'] = __('maps_invalid_input');
    header('Location: ' . $returnUrl);
    exit;
}

if (empty($entryValue) || !filter_var($entryValue, FILTER_VALIDATE_EMAIL)) {
    $_SESSION['error_msg'] = __('maps_invalid_value');
    header('Location: ' . $returnUrl);
    exit;
}

if (!checkPermission('admin') && !checkDomainAccess($entryValue)) {
    $_SESSION['error_msg'] = __('maps_permission_denied');
    header('Location: ' . $returnUrl);
    exit;
}

$score = $listType === 'whitelist' ? -10 : 10;

$db = Database::getInstance()->getConnection();
$user = $_SESSION['username'] ?? 'unknown';

$checkStmt = $db->prepare("SELECT COUNT(*) FROM rspamd_map_entries WHERE list_type = ? AND entry_type = ? AND entry_value = ?");
$checkStmt->execute([$listType, $entryType, $entryValue]);
if ($checkStmt->fetchColumn() > 0) {
    $_SESSION['error_msg'] = __('maps_duplicate');
    header('Location: ' . $returnUrl);
    exit;
}

$insertStmt = $db->prepare("INSERT INTO rspamd_map_entries (list_type, entry_type, entry_value, score, created_by, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, NOW(), NOW())");
$insertStmt->execute([$listType, $entryType, $entryValue, $score, $user]);

$mapName = getRspamdMapName($listType, $entryType);
if (!$mapName) {
    $_SESSION['error_msg'] = __('maps_config_missing');
    header('Location: ' . $returnUrl);
    exit;
}

$stmt = $db->prepare("SELECT entry_value, score FROM rspamd_map_entries WHERE list_type = ? AND entry_type = ? ORDER BY entry_value ASC");
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

$_SESSION['success_msg'] = __('maps_added');
header('Location: ' . $returnUrl);
exit;
