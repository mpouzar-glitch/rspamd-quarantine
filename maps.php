<?php
/*
 * Version: 2.0.0
 * Author: Martin Pouzar
 * License: GNU General Public License v3.0
 */
/**
 * Rspamd Quarantine - Whitelist/Blacklist Maps
 */

session_start();
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/lang_helper.php';

requireAuth();

if (!checkPermission('domain_admin')) {
    $_SESSION['error_msg'] = __('msg_access_denied');
    header('Location: index.php');
    exit;
}

$db = Database::getInstance()->getConnection();
$user = $_SESSION['username'] ?? 'unknown';
$userId = $_SESSION['user_id'] ?? null;
$userRole = $_SESSION['user_role'] ?? 'viewer';
$isDomainAdmin = $userRole === 'domain_admin';

$allowedLists = ['whitelist', 'blacklist'];
$entryTypes = [
    'ip' => __('maps_type_ip'),
    'email' => __('maps_type_email_domain'),
    'email_regex' => __('maps_type_email_regex'),
    'subject' => __('maps_type_subject'),
];
$allowedTypes = array_keys($entryTypes);

function validateMapEntry($entryType, $value) {
    if ($entryType === 'ip') {
        return filter_var($value, FILTER_VALIDATE_IP) !== false;
    }

    if ($entryType === 'email') {
        return isValidMapEmailEntry($value);
    }

    if ($entryType === 'email_regex') {
        return isRegexMapEntry($value);
    }

    if ($entryType === 'subject') {
        return isRegexMapEntry($value);
    }

    return false;
}

function canManageMapEntry($entryType, $entryValue, $isDomainAdmin) {
    if (!$isDomainAdmin) {
        return true;
    }

    if ($entryType === 'email' || $entryType === 'email_regex') {
        return canManageEmailMapEntry($entryValue);
    }

    return true;
}

function syncMapEntries($db, $listType, $entryType) {
    $mapName = getRspamdMapName($listType, $entryType);
    if (!$mapName) {
        return [
            'success' => false,
            'error' => __('maps_config_missing'),
        ];
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

        return [
            'success' => false,
            'error' => empty($errors)
                ? __('maps_upload_failed_generic')
                : __('maps_upload_failed', ['servers' => implode(', ', $errors)]),
        ];
    }

    return ['success' => true];
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    if ($action === 'add') {
        $listType = $_POST['list_type'] ?? '';
        $entryType = $_POST['entry_type'] ?? '';
        $entryValue = trim($_POST['entry_value'] ?? '');
        if (!in_array($listType, $allowedLists, true) || !in_array($entryType, $allowedTypes, true)) {
            $_SESSION['error_msg'] = __('maps_invalid_input');
            header('Location: maps.php');
            exit;
        }

        if (empty($entryValue) || !validateMapEntry($entryType, $entryValue)) {
            $_SESSION['error_msg'] = __('maps_invalid_value');
            header('Location: maps.php');
            exit;
        }

        if (!canManageMapEntry($entryType, $entryValue, $isDomainAdmin)) {
            $_SESSION['error_msg'] = __('maps_permission_denied');
            header('Location: maps.php');
            exit;
        }

        $checkStmt = $db->prepare("SELECT COUNT(*) FROM rspamd_map_entries WHERE list_type = ? AND entry_type = ? AND entry_value = ?");
        $checkStmt->execute([$listType, $entryType, $entryValue]);
        if ($checkStmt->fetchColumn() > 0) {
            $_SESSION['error_msg'] = __('maps_duplicate');
            header('Location: maps.php');
            exit;
        }

        $insertStmt = $db->prepare("INSERT INTO rspamd_map_entries (list_type, entry_type, entry_value, created_by, created_at, updated_at)
            VALUES (?, ?, ?, ?, NOW(), NOW())");
        $insertStmt->execute([$listType, $entryType, $entryValue, $user]);
        $entryId = $db->lastInsertId();
        $details = sprintf(
            'Added %s %s entry: %s (created by %s)',
            $listType,
            $entryType,
            $entryValue,
            $user
        );
        logAudit($userId, $user, 'map_add', 'rspamd_map_entry', $entryId, $details);

        $sync = syncMapEntries($db, $listType, $entryType);
        if ($sync['success']) {
            $_SESSION['success_msg'] = __('maps_added');
        } else {
            $_SESSION['error_msg'] = $sync['error'] ?? __('maps_upload_failed_generic');
        }

        header('Location: maps.php');
        exit;
    }

    if ($action === 'delete') {
        $entryId = (int)($_POST['id'] ?? 0);

        if ($entryId <= 0) {
            $_SESSION['error_msg'] = __('maps_invalid_input');
            header('Location: maps.php');
            exit;
        }

        $entryStmt = $db->prepare("SELECT list_type, entry_type, entry_value, created_by FROM rspamd_map_entries WHERE id = ?");
        $entryStmt->execute([$entryId]);
        $entry = $entryStmt->fetch(PDO::FETCH_ASSOC);

        if (!$entry) {
            $_SESSION['error_msg'] = __('maps_not_found');
            header('Location: maps.php');
            exit;
        }

        if ($isDomainAdmin && $entry['created_by'] !== $user) {
            $_SESSION['error_msg'] = __('maps_permission_denied');
            header('Location: maps.php');
            exit;
        }

        $deleteStmt = $db->prepare("DELETE FROM rspamd_map_entries WHERE id = ?");
        $deleteStmt->execute([$entryId]);
        $details = sprintf(
            'Deleted %s %s entry: %s (created by %s)',
            $entry['list_type'],
            $entry['entry_type'],
            $entry['entry_value'],
            $entry['created_by']
        );
        logAudit($userId, $user, 'map_delete', 'rspamd_map_entry', $entryId, $details);

        $sync = syncMapEntries($db, $entry['list_type'], $entry['entry_type']);
        if ($sync['success']) {
            $_SESSION['success_msg'] = __('maps_deleted');
        } else {
            $_SESSION['error_msg'] = $sync['error'] ?? __('maps_upload_failed_generic');
        }

        header('Location: maps.php');
        exit;
    }
}

if ($isDomainAdmin) {
    $stmt = $db->prepare("SELECT id, list_type, entry_type, entry_value, created_by, created_at
        FROM rspamd_map_entries
        WHERE created_by = ?
        ORDER BY list_type ASC, entry_type ASC, entry_value ASC");
    $stmt->execute([$user]);
    $entries = $stmt->fetchAll(PDO::FETCH_ASSOC);
} else {
    $stmt = $db->query("SELECT id, list_type, entry_type, entry_value, created_by, created_at
        FROM rspamd_map_entries
        ORDER BY list_type ASC, entry_type ASC, entry_value ASC");
    $entries = $stmt->fetchAll(PDO::FETCH_ASSOC);
}

$whitelistEntries = array_values(array_filter($entries, function ($entry) {
    return $entry['list_type'] === 'whitelist';
}));

$blacklistEntries = array_values(array_filter($entries, function ($entry) {
    return $entry['list_type'] === 'blacklist';
}));

$groupEntriesByType = function (array $entries, array $types) {
    $grouped = [];
    foreach ($types as $type => $label) {
        $grouped[$type] = [];
    }

    foreach ($entries as $entry) {
        if (!isset($grouped[$entry['entry_type']])) {
            continue;
        }
        $grouped[$entry['entry_type']][] = $entry;
    }

    return $grouped;
};

$whitelistEntriesByType = $groupEntriesByType($whitelistEntries, $entryTypes);
$blacklistEntriesByType = $groupEntriesByType($blacklistEntries, $entryTypes);

$page_title = __('maps_title');
include 'menu.php';
?>

<!DOCTYPE html>
<html lang="<?php echo htmlspecialchars(currentLang()); ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($page_title); ?></title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link rel="stylesheet" href="css/style.css">
    <link rel="stylesheet" href="css/index.css">
    <link rel="stylesheet" href="css/maps.css">
</head>
<body>
    <div class="container">
        <div class="header-with-stats">
            <div class="header-title">
                <h1><i class="fas fa-list-check"></i> <?php echo htmlspecialchars(__('maps_heading')); ?></h1>
            </div>
        </div>

        <div class="maps-grid">
            <div class="maps-panel">
                <div class="maps-panel-header">
                    <h2><i class="fas fa-shield-alt"></i> <?php echo htmlspecialchars(__('maps_whitelist')); ?></h2>
                    <p><?php echo htmlspecialchars(__('maps_whitelist_desc')); ?></p>
                </div>

                <form method="post" class="maps-form">
                    <input type="hidden" name="action" value="add">
                    <input type="hidden" name="list_type" value="whitelist">

                    <div class="form-grid">
                        <div class="form-group">
                            <label for="whitelist-entry-type"><?php echo htmlspecialchars(__('maps_entry_type')); ?></label>
                            <select id="whitelist-entry-type" name="entry_type" required>
                                <?php foreach ($entryTypes as $type => $label): ?>
                                    <option value="<?php echo htmlspecialchars($type); ?>">
                                        <?php echo htmlspecialchars($label); ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div class="form-group">
                            <label for="whitelist-entry-value"><?php echo htmlspecialchars(__('maps_entry_value')); ?></label>
                            <input id="whitelist-entry-value" type="text" name="entry_value" placeholder="<?php echo htmlspecialchars(__('maps_value_placeholder')); ?>" required>
                        </div>
                    </div>

                    <button type="submit" class="btn btn-primary">
                        <i class="fas fa-plus"></i> <?php echo htmlspecialchars(__('maps_add_entry')); ?>
                    </button>
                </form>

                <div class="maps-tabs" data-list="whitelist">
                    <?php $firstTab = true; ?>
                    <?php foreach ($entryTypes as $type => $label): ?>
                        <button type="button" class="maps-tab<?php echo $firstTab ? ' active' : ''; ?>" data-target="whitelist-<?php echo htmlspecialchars($type); ?>">
                            <?php echo htmlspecialchars($label); ?>
                        </button>
                        <?php $firstTab = false; ?>
                    <?php endforeach; ?>
                </div>

                <?php $firstGroup = true; ?>
                <?php foreach ($entryTypes as $type => $label): ?>
                    <div class="maps-group<?php echo $firstGroup ? ' active' : ''; ?>" data-group="whitelist-<?php echo htmlspecialchars($type); ?>">
                        <table class="messages-table maps-table">
                            <thead>
                                <tr>
                                    <th><?php echo htmlspecialchars(__('maps_entry_value')); ?></th>
                                    <th><?php echo htmlspecialchars(__('maps_created_by')); ?></th>
                                    <th style="width: 160px;"><?php echo htmlspecialchars(__('maps_created_at')); ?></th>
                                    <th style="width: 90px;"><?php echo htmlspecialchars(__('actions')); ?></th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php if (empty($whitelistEntriesByType[$type])): ?>
                                    <tr>
                                        <td colspan="4" class="no-results">
                                            <?php echo htmlspecialchars(__('maps_no_entries')); ?>
                                        </td>
                                    </tr>
                                <?php else: ?>
                                    <?php foreach ($whitelistEntriesByType[$type] as $entry): ?>
                                        <tr>
                                            <td><?php echo htmlspecialchars($entry['entry_value']); ?></td>
                                            <td><?php echo htmlspecialchars($entry['created_by'] ?? '-'); ?></td>
                                            <td><?php echo htmlspecialchars(date('d.m.Y H:i', strtotime($entry['created_at']))); ?></td>
                                            <td>
                                                <form method="post" class="inline-form" onsubmit="return confirm('<?php echo htmlspecialchars(__('maps_confirm_delete')); ?>');">
                                                    <input type="hidden" name="action" value="delete">
                                                    <input type="hidden" name="id" value="<?php echo (int)$entry['id']; ?>">
                                                    <button type="submit" class="action-btn delete-btn" title="<?php echo htmlspecialchars(__('delete')); ?>">
                                                        <i class="fas fa-trash"></i>
                                                    </button>
                                                </form>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                <?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                    <?php $firstGroup = false; ?>
                <?php endforeach; ?>
            </div>

            <div class="maps-panel">
                <div class="maps-panel-header">
                    <h2><i class="fas fa-ban"></i> <?php echo htmlspecialchars(__('maps_blacklist')); ?></h2>
                    <p><?php echo htmlspecialchars(__('maps_blacklist_desc')); ?></p>
                </div>

                <form method="post" class="maps-form">
                    <input type="hidden" name="action" value="add">
                    <input type="hidden" name="list_type" value="blacklist">

                    <div class="form-grid">
                        <div class="form-group">
                            <label for="blacklist-entry-type"><?php echo htmlspecialchars(__('maps_entry_type')); ?></label>
                            <select id="blacklist-entry-type" name="entry_type" required>
                                <?php foreach ($entryTypes as $type => $label): ?>
                                    <option value="<?php echo htmlspecialchars($type); ?>">
                                        <?php echo htmlspecialchars($label); ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div class="form-group">
                            <label for="blacklist-entry-value"><?php echo htmlspecialchars(__('maps_entry_value')); ?></label>
                            <input id="blacklist-entry-value" type="text" name="entry_value" placeholder="<?php echo htmlspecialchars(__('maps_value_placeholder')); ?>" required>
                        </div>
                    </div>

                    <button type="submit" class="btn btn-primary">
                        <i class="fas fa-plus"></i> <?php echo htmlspecialchars(__('maps_add_entry')); ?>
                    </button>
                </form>

                <div class="maps-tabs" data-list="blacklist">
                    <?php $firstTab = true; ?>
                    <?php foreach ($entryTypes as $type => $label): ?>
                        <button type="button" class="maps-tab<?php echo $firstTab ? ' active' : ''; ?>" data-target="blacklist-<?php echo htmlspecialchars($type); ?>">
                            <?php echo htmlspecialchars($label); ?>
                        </button>
                        <?php $firstTab = false; ?>
                    <?php endforeach; ?>
                </div>

                <?php $firstGroup = true; ?>
                <?php foreach ($entryTypes as $type => $label): ?>
                    <div class="maps-group<?php echo $firstGroup ? ' active' : ''; ?>" data-group="blacklist-<?php echo htmlspecialchars($type); ?>">
                        <table class="messages-table maps-table">
                            <thead>
                                <tr>
                                    <th><?php echo htmlspecialchars(__('maps_entry_value')); ?></th>
                                    <th><?php echo htmlspecialchars(__('maps_created_by')); ?></th>
                                    <th style="width: 160px;"><?php echo htmlspecialchars(__('maps_created_at')); ?></th>
                                    <th style="width: 90px;"><?php echo htmlspecialchars(__('actions')); ?></th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php if (empty($blacklistEntriesByType[$type])): ?>
                                    <tr>
                                        <td colspan="4" class="no-results">
                                            <?php echo htmlspecialchars(__('maps_no_entries')); ?>
                                        </td>
                                    </tr>
                                <?php else: ?>
                                    <?php foreach ($blacklistEntriesByType[$type] as $entry): ?>
                                        <tr>
                                            <td><?php echo htmlspecialchars($entry['entry_value']); ?></td>
                                            <td><?php echo htmlspecialchars($entry['created_by'] ?? '-'); ?></td>
                                            <td><?php echo htmlspecialchars(date('d.m.Y H:i', strtotime($entry['created_at']))); ?></td>
                                            <td>
                                                <form method="post" class="inline-form" onsubmit="return confirm('<?php echo htmlspecialchars(__('maps_confirm_delete')); ?>');">
                                                    <input type="hidden" name="action" value="delete">
                                                    <input type="hidden" name="id" value="<?php echo (int)$entry['id']; ?>">
                                                    <button type="submit" class="action-btn delete-btn" title="<?php echo htmlspecialchars(__('delete')); ?>">
                                                        <i class="fas fa-trash"></i>
                                                    </button>
                                                </form>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                <?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                    <?php $firstGroup = false; ?>
                <?php endforeach; ?>
            </div>
        </div>
    </div>

    <script>
        document.querySelectorAll('.maps-tabs').forEach((tabContainer) => {
            tabContainer.addEventListener('click', (event) => {
                const target = event.target.closest('.maps-tab');
                if (!target) {
                    return;
                }

                const panel = tabContainer.closest('.maps-panel');
                if (!panel) {
                    return;
                }

                panel.querySelectorAll('.maps-tab').forEach((tab) => {
                    tab.classList.toggle('active', tab === target);
                });

                const groupId = target.getAttribute('data-target');
                panel.querySelectorAll('.maps-group').forEach((group) => {
                    group.classList.toggle('active', group.getAttribute('data-group') === groupId);
                });
            });
        });
    </script>
</body>
</html>
