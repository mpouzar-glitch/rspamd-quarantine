<?php
/**
 * Rspamd Quarantine - User Management
 * Version: 2.0.4
 * Updated: Full UI refresh and working domain assignments
 */

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/lang_helper.php';
requireAuth();

if (!checkPermission('domain_admin')) {
    $_SESSION['error_msg'] = __('users_access_denied');
    header('Location: index.php');
    exit;
}

$db = Database::getInstance()->getConnection();
$userRole = $_SESSION['user_role'] ?? 'viewer';
$isAdmin = $userRole === 'admin';
$canEditQuota = $isAdmin;
$isConfigDbPostfix = defined('POSTFIX_DB_HOST') ? true : false;
$canManagePostfix = defined('POSTFIX_ALLOW_MAILBOX_EDIT') ? (bool) POSTFIX_ALLOW_MAILBOX_EDIT : true;
$passwordMinLength = defined('PASSWORD_MIN_LENGTH') ? (int) PASSWORD_MIN_LENGTH : 8;
$postfixError = null;
$postfixDb = getPostfixConnection($postfixError);

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    switch ($action) {
        case 'add':
            if (!$isAdmin) {
                $_SESSION['error_msg'] = __('users_access_denied');
                break;
            }
            $username = trim($_POST['username']);
            $password = $_POST['password'];
            $emailInput = trim($_POST['email']);
            $role = $_POST['role'];
            $domains_text = $_POST['domains'] ?? '';
            $active = isset($_POST['active']) ? 1 : 0;

            // Validate
            if (empty($username) || empty($password) || empty($emailInput) || empty($role)) {
                $_SESSION['error_msg'] = __('users_required_fields');
                break;
            }

            $passwordLength = function_exists('mb_strlen') ? mb_strlen($password) : strlen($password);
            if ($passwordLength < $passwordMinLength) {
                $_SESSION['error_msg'] = __('users_password_too_short', ['min' => $passwordMinLength]);
                break;
            }

            $invalidEmails = [];
            if ($role === 'quarantine_user') {
                $emails = parseEmailList($emailInput, $invalidEmails);
                if (empty($emails) || !empty($invalidEmails)) {
                    $_SESSION['error_msg'] = __('users_invalid_emails');
                    break;
                }
                $email = implode("\n", $emails);
            } else {
                if (!filter_var($emailInput, FILTER_VALIDATE_EMAIL)) {
                    $_SESSION['error_msg'] = __('users_invalid_email');
                    break;
                }
                $email = $emailInput;
            }

            // Check if username exists
            $stmt = $db->prepare("SELECT id FROM users WHERE username = ?");
            $stmt->execute([$username]);
            if ($stmt->fetch()) {
                $_SESSION['error_msg'] = __('users_username_exists');
                break;
            }

            // Hash password
            $password_hash = password_hash($password, PASSWORD_DEFAULT);

            try {
                $db->beginTransaction();

                // Insert user
                $stmt = $db->prepare("
                    INSERT INTO users (username, password_hash, email, role, active, created_at)
                    VALUES (?, ?, ?, ?, ?, NOW())
                ");
                $stmt->execute([$username, $password_hash, $email, $role, $active]);
                $user_id = $db->lastInsertId();

                // Insert domains for domain_admin (one per line)
                if ($role === 'domain_admin' && !empty($domains_text)) {
                    $domains = array_filter(array_map('trim', explode("\n", $domains_text)));
                    $stmt = $db->prepare("INSERT INTO user_domains (user_id, domain) VALUES (?, ?)");
                    foreach ($domains as $domain) {
                        if (!empty($domain)) {
                            $stmt->execute([$user_id, $domain]);
                        }
                    }
                }

                $db->commit();
                logAudit($_SESSION['user_id'], $_SESSION['username'], 'user_created', 'users', $user_id, "Created user: $username");
                $_SESSION['success_msg'] = __('users_create_success');

            } catch (Exception $e) {
                $db->rollBack();
                $_SESSION['error_msg'] = __('users_create_error', ['error' => $e->getMessage()]);
            }
            break;

        case 'edit':
            if (!$isAdmin) {
                $_SESSION['error_msg'] = __('users_access_denied');
                break;
            }
            $user_id = intval($_POST['user_id']);
            $username = trim($_POST['username']);
            $emailInput = trim($_POST['email']);
            $role = $_POST['role'];
            $domains_text = $_POST['domains'] ?? '';
            $active = isset($_POST['active']) ? 1 : 0;
            $password = $_POST['password'] ?? '';

            // Validate
            if (empty($username) || empty($emailInput) || empty($role)) {
                $_SESSION['error_msg'] = __('users_required_fields');
                break;
            }

            if ($password !== '') {
                $passwordLength = function_exists('mb_strlen') ? mb_strlen($password) : strlen($password);
                if ($passwordLength < $passwordMinLength) {
                    $_SESSION['error_msg'] = __('users_password_too_short', ['min' => $passwordMinLength]);
                    break;
                }
            }

            $invalidEmails = [];
            if ($role === 'quarantine_user') {
                $emails = parseEmailList($emailInput, $invalidEmails);
                if (empty($emails) || !empty($invalidEmails)) {
                    $_SESSION['error_msg'] = __('users_invalid_emails');
                    break;
                }
                $email = implode("\n", $emails);
            } else {
                if (!filter_var($emailInput, FILTER_VALIDATE_EMAIL)) {
                    $_SESSION['error_msg'] = __('users_invalid_email');
                    break;
                }
                $email = $emailInput;
            }

            // Check if username exists (except current user)
            $stmt = $db->prepare("SELECT id FROM users WHERE username = ? AND id != ?");
            $stmt->execute([$username, $user_id]);
            if ($stmt->fetch()) {
                $_SESSION['error_msg'] = __('users_username_exists');
                break;
            }

            try {
                $currentStmt = $db->prepare("SELECT username, email, role, active FROM users WHERE id = ?");
                $currentStmt->execute([$user_id]);
                $currentUser = $currentStmt->fetch();
                if (!$currentUser) {
                    $_SESSION['error_msg'] = __('users_update_error', ['error' => __('users_not_found')]);
                    break;
                }

                $domainStmt = $db->prepare("SELECT domain FROM user_domains WHERE user_id = ? ORDER BY domain");
                $domainStmt->execute([$user_id]);
                $currentDomains = $domainStmt->fetchAll(PDO::FETCH_COLUMN);
                $updatedDomains = [];
                if ($role === 'domain_admin' && !empty($domains_text)) {
                    $updatedDomains = array_filter(array_map('trim', explode("\n", $domains_text)));
                }

                $db->beginTransaction();

                // Update user
                if (!empty($password)) {
                    $password_hash = password_hash($password, PASSWORD_DEFAULT);
                    $stmt = $db->prepare("
                        UPDATE users 
                        SET username = ?, password_hash = ?, email = ?, role = ?, active = ?
                        WHERE id = ?
                    ");
                    $stmt->execute([$username, $password_hash, $email, $role, $active, $user_id]);
                } else {
                    $stmt = $db->prepare("
                        UPDATE users 
                        SET username = ?, email = ?, role = ?, active = ?
                        WHERE id = ?
                    ");
                    $stmt->execute([$username, $email, $role, $active, $user_id]);
                }

                // Update domains for domain_admin (one per line)
                $stmt = $db->prepare("DELETE FROM user_domains WHERE user_id = ?");
                $stmt->execute([$user_id]);

                if ($role === 'domain_admin' && !empty($domains_text)) {
                    $domains = array_filter(array_map('trim', explode("\n", $domains_text)));
                    $stmt = $db->prepare("INSERT INTO user_domains (user_id, domain) VALUES (?, ?)");
                    foreach ($domains as $domain) {
                        if (!empty($domain)) {
                            $stmt->execute([$user_id, $domain]);
                        }
                    }
                }

                $db->commit();
                $changes = [];
                if ($currentUser['username'] !== $username) {
                    $changes[] = "username: {$currentUser['username']} → {$username}";
                }
                if ($currentUser['email'] !== $email) {
                    $changes[] = "email: {$currentUser['email']} → {$email}";
                }
                if ($currentUser['role'] !== $role) {
                    $changes[] = "role: {$currentUser['role']} → {$role}";
                }
                if ((int)$currentUser['active'] !== $active) {
                    $changes[] = 'active: ' . ((int)$currentUser['active'] ? 'yes' : 'no') . ' → ' . ($active ? 'yes' : 'no');
                }
                if (!empty($password)) {
                    $changes[] = 'password updated';
                }

                if ($role === 'domain_admin') {
                    $addedDomains = array_diff($updatedDomains, $currentDomains);
                    $removedDomains = array_diff($currentDomains, $updatedDomains);
                    if (!empty($addedDomains)) {
                        $changes[] = 'domains added: ' . implode(', ', $addedDomains);
                    }
                    if (!empty($removedDomains)) {
                        $changes[] = 'domains removed: ' . implode(', ', $removedDomains);
                    }
                } elseif (!empty($currentDomains)) {
                    $changes[] = 'domains cleared';
                }

                $details = 'Updated user: ' . $username;
                if (!empty($changes)) {
                    $details .= ' | Changes: ' . implode('; ', $changes);
                }
                logAudit($_SESSION['user_id'], $_SESSION['username'], 'user_updated', 'users', $user_id, $details);
                $_SESSION['success_msg'] = __('users_update_success');

            } catch (Exception $e) {
                $db->rollBack();
                $_SESSION['error_msg'] = __('users_update_error', ['error' => $e->getMessage()]);
            }
            break;

        case 'delete':
            if (!$isAdmin) {
                $_SESSION['error_msg'] = __('users_access_denied');
                break;
            }
            $user_id = intval($_POST['user_id']);

            // Prevent deleting yourself
            if ($user_id == $_SESSION['user_id']) {
                $_SESSION['error_msg'] = __('users_delete_self_error');
                break;
            }

            try {
                $db->beginTransaction();

                // Get username for audit
                $stmt = $db->prepare("SELECT username FROM users WHERE id = ?");
                $stmt->execute([$user_id]);
                $user = $stmt->fetch();

                // Delete user domains
                $stmt = $db->prepare("DELETE FROM user_domains WHERE user_id = ?");
                $stmt->execute([$user_id]);

                // Delete user
                $stmt = $db->prepare("DELETE FROM users WHERE id = ?");
                $stmt->execute([$user_id]);

                $db->commit();
                logAudit($_SESSION['user_id'], $_SESSION['username'], 'user_deleted', 'users', $user_id, "Deleted user: " . $user['username']);
                $_SESSION['success_msg'] = __('users_delete_success');

            } catch (Exception $e) {
                $db->rollBack();
                $_SESSION['error_msg'] = __('users_delete_error', ['error' => $e->getMessage()]);
            }
            break;

        case 'mailbox_create':
            if (!$canManagePostfix) {
                $_SESSION['error_msg'] = __('users_mailbox_access_denied');
                break;
            }
            $localPart = trim($_POST['mailbox_local'] ?? '');
            $domain = trim($_POST['domain'] ?? '');
            $name = trim($_POST['name'] ?? '');
            $quotaGb = isset($_POST['quota']) ? max(0, (float)$_POST['quota']) : 0;
            $quota = (int) round($quotaGb * 1024);
            $active = isset($_POST['active']) ? 1 : 0;
            $password = $_POST['password'] ?? '';

            if ($localPart === '' || $domain === '' || $name === '' || $password === '') {
                $_SESSION['error_msg'] = __('users_mailbox_create_required_fields');
                break;
            }

            if (str_contains($localPart, '@')) {
                $_SESSION['error_msg'] = __('users_mailbox_invalid_localpart');
                break;
            }

            $mailbox = $localPart . '@' . $domain;
            if (!filter_var($mailbox, FILTER_VALIDATE_EMAIL)) {
                $_SESSION['error_msg'] = __('users_mailbox_invalid_address');
                break;
            }

            if (!hasDomainAccess($domain)) {
                $_SESSION['error_msg'] = __('users_mailbox_access_denied');
                break;
            }

            if (!$postfixDb) {
                $_SESSION['error_msg'] = __('users_mailbox_db_unavailable');
                break;
            }

            try {
                $stmt = $postfixDb->prepare("SELECT username FROM mailbox WHERE username = ? AND domain = ?");
                $stmt->execute([$mailbox, $domain]);
                if ($stmt->fetch()) {
                    $_SESSION['error_msg'] = __('users_mailbox_exists');
                    break;
                }

                $stmt = $postfixDb->prepare("SELECT address FROM alias WHERE address = ? AND domain = ?");
                $stmt->execute([$mailbox, $domain]);
                if ($stmt->fetch()) {
                    $_SESSION['error_msg'] = __('users_alias_exists');
                    break;
                }

                $maildir = $domain . '/' . $localPart . '/';
                $passwordHash = generateMd5CryptPassword($password);

                $postfixDb->beginTransaction();
                $stmt = $postfixDb->prepare("
                    INSERT INTO mailbox (username, password, name, maildir, quota, domain, active, created, modified)
                    VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), NOW())
                ");
                $stmt->execute([$mailbox, $passwordHash, $name, $maildir, $canEditQuota ? $quota : 0, $domain, $active]);

                $stmt = $postfixDb->prepare("
                    INSERT INTO alias (address, domain, goto, active, created, modified)
                    VALUES (?, ?, ?, ?, NOW(), NOW())
                ");
                $stmt->execute([$mailbox, $domain, $mailbox, $active]);
                $postfixDb->commit();

                logAudit(
                    $_SESSION['user_id'],
                    $_SESSION['username'],
                    'mailbox_created',
                    'mailbox',
                    null,
                    'Created mailbox: ' . $mailbox . ' (' . $domain . ') + system alias'
                );
                $_SESSION['success_msg'] = __('users_mailbox_create_success');
            } catch (Exception $e) {
                if ($postfixDb->inTransaction()) {
                    $postfixDb->rollBack();
                }
                $_SESSION['error_msg'] = __('users_mailbox_create_error', ['error' => $e->getMessage()]);
            }
            break;

        case 'mailbox_update':
            if (!$canManagePostfix) {
                $_SESSION['error_msg'] = __('users_mailbox_access_denied');
                break;
            }
            $mailbox = trim($_POST['mailbox'] ?? '');
            $domain = trim($_POST['domain'] ?? '');
            $name = trim($_POST['name'] ?? '');
            $quotaGb = isset($_POST['quota']) ? max(0, (float)$_POST['quota']) : 0;
            $quota = (int) round($quotaGb * 1024);
            $active = isset($_POST['active']) ? 1 : 0;
            $password = $_POST['password'] ?? '';

            if ($mailbox === '' || $domain === '' || $name === '') {
                $_SESSION['error_msg'] = __('users_mailbox_required_fields');
                break;
            }

            if (!hasDomainAccess($domain)) {
                $_SESSION['error_msg'] = __('users_mailbox_access_denied');
                break;
            }

            if (!$postfixDb) {
                $_SESSION['error_msg'] = __('users_mailbox_db_unavailable');
                break;
            }

            try {
                $sql = "UPDATE mailbox SET name = ?, active = ?";
                $params = [$name, $active];

                if ($canEditQuota) {
                    $sql .= ", quota = ?";
                    $params[] = $quota;
                }

                if ($password !== '') {
                    $sql .= ", password = ?";
                    $params[] = generateMd5CryptPassword($password);
                }

                $sql .= ", modified = NOW() WHERE username = ? AND domain = ?";
                $params[] = $mailbox;
                $params[] = $domain;

                $stmt = $postfixDb->prepare($sql);
                $stmt->execute($params);

                logAudit(
                    $_SESSION['user_id'],
                    $_SESSION['username'],
                    'mailbox_updated',
                    'mailbox',
                    null,
                    'Updated mailbox: ' . $mailbox . ' (' . $domain . ')'
                );
                $_SESSION['success_msg'] = __('users_mailbox_update_success');
            } catch (Exception $e) {
                $_SESSION['error_msg'] = __('users_mailbox_update_error', ['error' => $e->getMessage()]);
            }
            break;

        case 'alias_create':
            if (!$canManagePostfix) {
                $_SESSION['error_msg'] = __('users_mailbox_access_denied');
                break;
            }
            $localPart = trim($_POST['alias_local'] ?? '');
            $domain = trim($_POST['domain'] ?? '');
            $goto = trim($_POST['goto'] ?? '');
            $active = isset($_POST['active']) ? 1 : 0;

            if ($localPart === '' || $domain === '' || $goto === '') {
                $_SESSION['error_msg'] = __('users_alias_required_fields');
                break;
            }

            if (str_contains($localPart, '@')) {
                $_SESSION['error_msg'] = __('users_alias_invalid_localpart');
                break;
            }

            $address = $localPart . '@' . $domain;
            if (!filter_var($address, FILTER_VALIDATE_EMAIL)) {
                $_SESSION['error_msg'] = __('users_alias_invalid_address');
                break;
            }

            if (!hasDomainAccess($domain)) {
                $_SESSION['error_msg'] = __('users_mailbox_access_denied');
                break;
            }

            if (!$postfixDb) {
                $_SESSION['error_msg'] = __('users_mailbox_db_unavailable');
                break;
            }

            try {
                $stmt = $postfixDb->prepare("SELECT address FROM alias WHERE address = ? AND domain = ?");
                $stmt->execute([$address, $domain]);
                if ($stmt->fetch()) {
                    $_SESSION['error_msg'] = __('users_alias_exists');
                    break;
                }

                $stmt = $postfixDb->prepare("
                    INSERT INTO alias (address, domain, goto, active, created, modified)
                    VALUES (?, ?, ?, ?, NOW(), NOW())
                ");
                $stmt->execute([$address, $domain, $goto, $active]);

                logAudit(
                    $_SESSION['user_id'],
                    $_SESSION['username'],
                    'alias_created',
                    'alias',
                    null,
                    'Created alias: ' . $address . ' (' . $domain . ') → ' . $goto
                );
                $_SESSION['success_msg'] = __('users_alias_create_success');
            } catch (Exception $e) {
                $_SESSION['error_msg'] = __('users_alias_create_error', ['error' => $e->getMessage()]);
            }
            break;

        case 'alias_update':
            if (!$canManagePostfix) {
                $_SESSION['error_msg'] = __('users_mailbox_access_denied');
                break;
            }
            $address = trim($_POST['address'] ?? '');
            $domain = trim($_POST['domain'] ?? '');
            $goto = trim($_POST['goto'] ?? '');
            $active = isset($_POST['active']) ? 1 : 0;

            if ($address === '' || $domain === '' || $goto === '') {
                $_SESSION['error_msg'] = __('users_alias_required_fields');
                break;
            }

            if (!hasDomainAccess($domain)) {
                $_SESSION['error_msg'] = __('users_mailbox_access_denied');
                break;
            }

            if (!$postfixDb) {
                $_SESSION['error_msg'] = __('users_mailbox_db_unavailable');
                break;
            }

            try {
                $stmt = $postfixDb->prepare("
                    UPDATE alias
                    SET goto = ?, active = ?, modified = NOW()
                    WHERE address = ? AND domain = ?
                ");
                $stmt->execute([$goto, $active, $address, $domain]);

                logAudit(
                    $_SESSION['user_id'],
                    $_SESSION['username'],
                    'alias_updated',
                    'alias',
                    null,
                    'Updated alias: ' . $address . ' (' . $domain . ')'
                );
                $_SESSION['success_msg'] = __('users_alias_update_success');
            } catch (Exception $e) {
                $_SESSION['error_msg'] = __('users_alias_update_error', ['error' => $e->getMessage()]);
            }
            break;
    }

    $redirectDomain = $_POST['domain'] ?? '';
    $redirectUrl = 'users.php';
    if (!empty($redirectDomain)) {
        $redirectUrl .= '?domain=' . urlencode($redirectDomain);
    }
    header('Location: ' . $redirectUrl);
    exit;
}

// Get all users with their domains (one per line)
if ($isAdmin) {
    $sql = "
        SELECT 
            u.*,
            GROUP_CONCAT(ud.domain SEPARATOR '\n') as domains
        FROM users u
        LEFT JOIN user_domains ud ON u.id = ud.user_id
        GROUP BY u.id
        ORDER BY u.username
    ";
    $users = $db->query($sql)->fetchAll();

    // Count statistics
    $total_users = count($users);
    $active_users = count(array_filter($users, function($u) { return $u['active']; }));
    $admin_count = count(array_filter($users, function($u) { return $u['role'] === 'admin'; }));
    $domain_admin_count = count(array_filter($users, function($u) { return $u['role'] === 'domain_admin'; }));
    $quarantine_user_count = count(array_filter($users, function($u) { return $u['role'] === 'quarantine_user'; }));
} else {
    $users = [];
    $total_users = 0;
    $active_users = 0;
    $admin_count = 0;
    $domain_admin_count = 0;
    $quarantine_user_count = 0;
}

$domainOptions = [];
$selectedDomain = '';
$mailboxes = [];
$aliases = [];
$hideSystemAliases = true;

if ($postfixDb) {
    if ($isAdmin) {
        $domainOptions = $postfixDb->query("SELECT domain FROM domain ORDER BY domain")->fetchAll(PDO::FETCH_COLUMN);
    } else {
        $userDomains = $_SESSION['user_domains'] ?? [];
        if (!empty($userDomains)) {
            $placeholders = implode(',', array_fill(0, count($userDomains), '?'));
            $stmt = $postfixDb->prepare("SELECT domain FROM domain WHERE domain IN ($placeholders) ORDER BY domain");
            $stmt->execute($userDomains);
            $domainOptions = $stmt->fetchAll(PDO::FETCH_COLUMN);
        }
    }

    if (!empty($domainOptions)) {
        $selectedDomain = $_GET['domain'] ?? $domainOptions[0];
        if (!in_array($selectedDomain, $domainOptions, true)) {
            $selectedDomain = $domainOptions[0];
        }
    }

    if ($selectedDomain !== '') {
        $stmt = $postfixDb->prepare("
            SELECT username, name, quota, active, maildir, domain
            FROM mailbox
            WHERE domain = ?
            ORDER BY username
        ");
        $stmt->execute([$selectedDomain]);
        $mailboxes = $stmt->fetchAll();

        $stmt = $postfixDb->prepare("
            SELECT address, goto, active, domain
            FROM alias
            WHERE domain = ?
            ORDER BY address
        ");
        $stmt->execute([$selectedDomain]);
        $aliases = $stmt->fetchAll();

        if (isset($_GET['hide_system_aliases'])) {
            $hideSystemAliases = $_GET['hide_system_aliases'] === '1';
        }
    }
}

if ($hideSystemAliases) {
    $aliases = array_values(array_filter($aliases, function ($alias) {
        return trim($alias['address']) !== trim($alias['goto']);
    }));
}

$baseMailDir = defined('VMAIL_BASE_DIR') ? VMAIL_BASE_DIR : '/var/vmail/vmail1';
$mailboxSizes = [];
foreach ($mailboxes as $mailbox) {
    $size = getMaildirSize($mailbox['maildir'], $baseMailDir);
    $mailboxSizes[$mailbox['username']] = $size;
}

$role_labels = [
    'admin' => __('role_admin'),
    'domain_admin' => __('role_domain_admin'),
    'quarantine_user' => __('role_quarantine_user'),
    'viewer' => __('role_viewer'),
];

$page_title = __('users_page_title', ['app' => __('app_title')]);
include 'menu.php';
?>
<!DOCTYPE html>
<html lang="<?php echo htmlspecialchars(currentLang()); ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($page_title); ?></title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link rel="stylesheet" href="style.css">
    <style>
        /* Inline Stats Styling */
        .header-with-stats {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 20px;
            gap: 30px;
            flex-wrap: wrap;
        }

        .header-title {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .header-title h1 {
            margin: 0;
            font-size: 28px;
            font-weight: 600;
            color: #2c3e50;
        }

        .header-title i {
            color: #3498db;
        }

        .stats-inline {
            display: flex;
            align-items: center;
            gap: 20px;
            flex-wrap: wrap;
            font-size: 13px;
        }

        .stat-inline-item {
            display: flex;
            align-items: center;
            gap: 6px;
            padding: 6px 12px;
            background: #f8f9fa;
            border-radius: 4px;
            border-left: 3px solid #95a5a6;
        }

        .stat-inline-item.total {
            border-left-color: #3498db;
        }

        .stat-inline-item.admin {
            border-left-color: #e74c3c;
        }

        .stat-inline-item.domain-admin {
            border-left-color: #f39c12;
        }

        .stat-inline-item.quarantine-user {
            border-left-color: #16a085;
        }

        .stat-inline-item.active {
            border-left-color: #27ae60;
        }

        .stat-inline-label {
            color: #7f8c8d;
            font-size: 11px;
            text-transform: uppercase;
            font-weight: 600;
        }

        .stat-inline-value {
            color: #2c3e50;
            font-weight: bold;
            font-size: 14px;
        }

        /* Button Styling */
        .action-buttons {
            margin-bottom: 20px;
        }

        .btn-add-user {
            background: linear-gradient(135deg, #27ae60 0%, #229954 100%);
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 6px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 8px;
            text-decoration: none;
            transition: all 0.2s;
            box-shadow: 0 2px 4px rgba(39, 174, 96, 0.3);
        }

        .btn-add-user:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(39, 174, 96, 0.4);
        }

        .section-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            flex-wrap: wrap;
            margin-bottom: 10px;
        }

        .section-header h3 {
            margin: 0;
        }

        .section-header-actions {
            display: flex;
            align-items: center;
            gap: 12px;
            flex-wrap: wrap;
        }

        .alias-filter-form {
            display: flex;
            align-items: center;
        }

        .checkbox-inline {
            display: flex;
            align-items: center;
            gap: 6px;
            font-size: 13px;
            color: #2c3e50;
        }

        /* Users Table - MAX 32px HEIGHT */
        .users-table {
            width: 100%;
            border-collapse: collapse;
            background: white;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
        }

        .users-table thead {
            background: linear-gradient(135deg, #34495e 0%, #2c3e50 100%);
            color: white;
        }

        .users-table th {
            padding: 8px 12px;
            text-align: left;
            font-size: 13px;
            font-weight: 600;
            height: 32px;
            vertical-align: middle;
        }

        .users-table td {
            padding: 6px 12px;
            border-bottom: 1px solid #e9ecef;
            font-size: 13px;
            max-height: 32px;
            height: 32px;
            vertical-align: middle;
            line-height: 20px;
        }

        .users-table tbody tr:hover {
            background-color: #f8f9fa;
        }

        .role-badge {
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 600;
            display: inline-block;
            line-height: 14px;
        }

        .role-admin {
            background: #ffebee;
            color: #c62828;
        }

        .role-domain-admin {
            background: #fff3e0;
            color: #e65100;
        }

        .role-quarantine-user {
            background: #e0f7f4;
            color: #00695c;
        }

        .role-viewer {
            background: #e3f2fd;
            color: #1565c0;
        }

        .status-badge {
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 600;
            display: inline-flex;
            align-items: center;
            gap: 4px;
            line-height: 14px;
        }

        .status-active {
            background: #e8f5e9;
            color: #2e7d32;
        }

        .status-inactive {
            background: #fce4ec;
            color: #c2185b;
        }

        .domains-list {
            font-size: 11px;
            color: #7f8c8d;
            max-width: 200px;
            max-height: 20px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            line-height: 20px;
        }

        .action-btn {
            padding: 4px 10px;
            border: none;
            border-radius: 4px;
            font-size: 11px;
            cursor: pointer;
            transition: all 0.2s;
            margin-right: 4px;
            display: inline-flex;
            align-items: center;
            gap: 4px;
            line-height: 16px;
        }

        .btn-edit {
            background: #3498db;
            color: white;
        }

        .btn-edit:hover {
            background: #2980b9;
        }

        .btn-delete {
            background: #e74c3c;
            color: white;
        }

        .btn-delete:hover {
            background: #c0392b;
        }

        .current-user {
            background: #fff8dc;
        }

        .no-results {
            text-align: center;
            padding: 60px 20px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        .no-results i {
            font-size: 64px;
            color: #bdc3c7;
            margin-bottom: 20px;
        }

        .no-results h3 {
            color: #7f8c8d;
            margin-bottom: 10px;
        }

        .domain-section {
            margin-top: 30px;
        }

        .domain-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 20px;
            flex-wrap: wrap;
            margin-bottom: 20px;
        }

        .domain-header h2 {
            margin: 0;
            font-size: 22px;
            color: #2c3e50;
        }

        .domain-selector {
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 13px;
        }

        .domain-selector select {
            padding: 8px 12px;
            border: 2px solid #e0e0e0;
            border-radius: 6px;
            font-size: 13px;
        }

        .domain-section .section-card {
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            padding: 20px;
            margin-bottom: 20px;
        }

        .domain-section h3 {
            margin-top: 0;
            margin-bottom: 15px;
            font-size: 18px;
            color: #2c3e50;
        }

        .mailbox-table,
        .alias-table {
            width: 100%;
            border-collapse: collapse;
        }

        .mailbox-table th,
        .mailbox-table td,
        .alias-table th,
        .alias-table td {
            padding: 8px 10px;
            border-bottom: 1px solid #e9ecef;
            font-size: 13px;
            text-align: left;
        }

        .mailbox-table th,
        .alias-table th {
            background: #f4f6f8;
            color: #2c3e50;
            font-weight: 600;
        }

        .alias-target {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            color: #2c3e50;
        }

        .alias-target i {
            color: #3498db;
        }

        .mailbox-actions button {
            padding: 4px 8px;
            font-size: 11px;
        }

        .mailbox-size {
            font-weight: 600;
            color: #34495e;
        }

        .domain-empty {
            color: #7f8c8d;
            font-size: 13px;
        }

        .readonly-field {
            background: #f4f6f8;
            color: #7f8c8d;
        }

        /* Modal Styling */
        .modal {
            display: none;
            position: fixed;
            z-index: 10000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            overflow: auto;
            background-color: rgba(0,0,0,0.5);
        }

        .modal-content {
            background-color: white;
            margin: 5% auto;
            padding: 0;
            border-radius: 8px;
            width: 90%;
            max-width: 600px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
        }

        .modal-header {
            background: linear-gradient(135deg, #34495e 0%, #2c3e50 100%);
            color: white;
            padding: 20px;
            border-radius: 8px 8px 0 0;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .modal-header h2 {
            margin: 0;
            font-size: 20px;
        }

        .close {
            color: white;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
            transition: color 0.2s;
        }

        .close:hover {
            color: #e74c3c;
        }

        .modal-body {
            padding: 20px;
        }

        .form-group {
            margin-bottom: 15px;
        }

        .form-group label {
            display: block;
            margin-bottom: 5px;
            font-weight: 600;
            color: #2c3e50;
            font-size: 13px;
        }

        .form-group input,
        .form-group select,
        .form-group textarea {
            width: 100%;
            padding: 10px;
            border: 2px solid #e0e0e0;
            border-radius: 6px;
            font-size: 14px;
            transition: border-color 0.2s;
        }

        .form-group input:focus,
        .form-group select:focus,
        .form-group textarea:focus {
            outline: none;
            border-color: #3498db;
        }

        .form-group textarea {
            resize: vertical;
            min-height: 80px;
        }

        .checkbox-group {
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .checkbox-group input[type="checkbox"] {
            width: auto;
        }

        .modal-footer {
            padding: 15px 20px;
            border-top: 1px solid #e9ecef;
            display: flex;
            justify-content: flex-end;
            gap: 10px;
        }

        .btn-submit {
            background: linear-gradient(135deg, #27ae60 0%, #229954 100%);
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 6px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }

        .btn-submit:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(39, 174, 96, 0.4);
        }

        .btn-cancel {
            background: #95a5a6;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 6px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
        }

        .btn-cancel:hover {
            background: #7f8c8d;
        }

        @media (max-width: 992px) {
            .header-with-stats {
                flex-direction: column;
                align-items: flex-start;
            }
        }

        @media (max-width: 768px) {
            .stats-inline {
                width: 100%;
            }

            .stat-inline-item {
                flex: 1 1 calc(50% - 10px);
                min-width: 140px;
            }

            .users-table {
                font-size: 11px;
            }

            .users-table th,
            .users-table td {
                padding: 5px 8px;
                height: 32px;
            }

            .modal-content {
                width: 95%;
                margin: 2% auto;
            }
        }
    </style>
</head>
<body>

<div class="container">
    <!-- HEADER WITH STATS -->
    <?php if ($isAdmin): ?>
        <div class="header-with-stats">
            <div class="header-title">
                <h1><i class="fas fa-users-cog"></i> <?php echo htmlspecialchars(__('users_title')); ?></h1>
            </div>
            <div class="stats-inline">
                <div class="stat-inline-item total">
                    <span class="stat-inline-label"><?php echo htmlspecialchars(__('users_total_label')); ?></span>
                    <span class="stat-inline-value"><?php echo $total_users; ?></span>
                </div>
                <div class="stat-inline-item active">
                    <span class="stat-inline-label"><?php echo htmlspecialchars(__('users_active_label')); ?></span>
                    <span class="stat-inline-value"><?php echo $active_users; ?></span>
                </div>
                <div class="stat-inline-item admin">
                    <span class="stat-inline-label"><?php echo htmlspecialchars(__('users_admin_label')); ?></span>
                    <span class="stat-inline-value"><?php echo $admin_count; ?></span>
                </div>
                <div class="stat-inline-item domain-admin">
                    <span class="stat-inline-label"><?php echo htmlspecialchars(__('users_domain_admin_label')); ?></span>
                    <span class="stat-inline-value"><?php echo $domain_admin_count; ?></span>
                </div>
                <div class="stat-inline-item quarantine-user">
                    <span class="stat-inline-label"><?php echo htmlspecialchars(__('users_quarantine_user_label')); ?></span>
                    <span class="stat-inline-value"><?php echo $quarantine_user_count; ?></span>
                </div>
            </div>
        </div>
    <?php else: ?>
        <div class="header-with-stats">
            <div class="header-title">
                <h1><i class="fas fa-globe"></i> <?php echo htmlspecialchars(__('users_domain_title')); ?></h1>
            </div>
        </div>
    <?php endif; ?>

    <?php displayAlerts(); ?>

    <?php if ($isAdmin): ?>
        <!-- ACTION BUTTONS -->
        <div class="action-buttons">
            <button class="btn-add-user" onclick="openAddModal()">
                <i class="fas fa-user-plus"></i> <?php echo htmlspecialchars(__('users_add')); ?>
            </button>
        </div>

        <!-- USERS TABLE -->
        <?php if (empty($users)): ?>
            <div class="no-results">
                <i class="fas fa-users"></i>
                <h3><?php echo htmlspecialchars(__('users_no_users_title')); ?></h3>
                <p><?php echo htmlspecialchars(__('users_no_users_desc')); ?></p>
            </div>
        <?php else: ?>
            <table class="users-table">
                <thead>
                    <tr>
                        <th style="width: 60px;">ID</th>
                        <th><?php echo htmlspecialchars(__('users_username')); ?></th>
                        <th><?php echo htmlspecialchars(__('users_email')); ?></th>
                        <th style="width: 130px;"><?php echo htmlspecialchars(__('users_role')); ?></th>
                        <th style="width: 200px;"><?php echo htmlspecialchars(__('users_domains')); ?></th>
                        <th style="width: 100px;"><?php echo htmlspecialchars(__('status')); ?></th>
                        <th style="width: 130px;"><?php echo htmlspecialchars(__('users_created')); ?></th>
                        <th style="width: 100px;"><?php echo htmlspecialchars(__('actions')); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($users as $user): ?>
                        <tr class="<?php echo ($user['id'] == $_SESSION['user_id']) ? 'current-user' : ''; ?>">
                            <td><?php echo $user['id']; ?></td>
                            <td>
                                <strong><?php echo htmlspecialchars($user['username']); ?></strong>
                                <?php if ($user['id'] == $_SESSION['user_id']): ?>
                                    <span style="color: #3498db; font-size: 10px;"> (<?php echo htmlspecialchars(__('users_label_you')); ?>)</span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <?php
                                $emailDisplay = $user['email'];
                                if ($user['role'] === 'quarantine_user') {
                                    $invalidEmails = [];
                                    $parsedEmails = parseEmailList($user['email'], $invalidEmails);
                                    if (!empty($parsedEmails)) {
                                        $emailDisplay = implode(', ', $parsedEmails);
                                    }
                                }
                                ?>
                                <?php echo htmlspecialchars($emailDisplay); ?>
                            </td>
                            <td>
                                <?php
                                $roleClass = 'role-viewer';
                                $roleName = $role_labels['viewer'];
                                if ($user['role'] === 'admin') {
                                    $roleClass = 'role-admin';
                                    $roleName = $role_labels['admin'];
                                } elseif ($user['role'] === 'domain_admin') {
                                    $roleClass = 'role-domain-admin';
                                    $roleName = $role_labels['domain_admin'];
                                } elseif ($user['role'] === 'quarantine_user') {
                                    $roleClass = 'role-quarantine-user';
                                    $roleName = $role_labels['quarantine_user'];
                                }
                                ?>
                                <span class="role-badge <?php echo $roleClass; ?>"><?php echo $roleName; ?></span>
                            </td>
                            <td>
                                <?php if (!empty($user['domains'])): ?>
                                    <div class="domains-list" title="<?php echo htmlspecialchars($user['domains']); ?>">
                                        <?php echo htmlspecialchars(str_replace("\n", ", ", $user['domains'])); ?>
                                    </div>
                                <?php else: ?>
                                    <span style="color: #95a5a6;">—</span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <?php if ($user['active']): ?>
                                    <span class="status-badge status-active">
                                        <i class="fas fa-check-circle"></i> <?php echo htmlspecialchars(__('users_active')); ?>
                                    </span>
                                <?php else: ?>
                                    <span class="status-badge status-inactive">
                                        <i class="fas fa-times-circle"></i> <?php echo htmlspecialchars(__('users_inactive')); ?>
                                    </span>
                                <?php endif; ?>
                            </td>
                            <td style="font-size: 11px; color: #7f8c8d;">
                                <?php echo date('d.m.Y H:i', strtotime($user['created_at'])); ?>
                            </td>
                            <td>
                                <button class="action-btn btn-edit" onclick='openEditModal(<?php echo json_encode($user); ?>)' title="<?php echo htmlspecialchars(__('edit')); ?>">
                                    <i class="fas fa-edit"></i>
                                </button>
                                <?php if ($user['id'] != $_SESSION['user_id']): ?>
                                    <button class="action-btn btn-delete" onclick="confirmDelete(<?php echo $user['id']; ?>, '<?php echo htmlspecialchars($user['username'], ENT_QUOTES); ?>')" title="<?php echo htmlspecialchars(__('delete')); ?>">
                                        <i class="fas fa-trash"></i>
                                    </button>
                                <?php endif; ?>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    <?php endif; ?>

  <?php if ($isConfigDbPostfix): ?>   
    <div class="domain-section">
        <div class="domain-header">
            <h2><i class="fas fa-envelope-open-text"></i> <?php echo htmlspecialchars(__('users_domain_section_title')); ?></h2>
            <?php if (!empty($domainOptions)): ?>
                <form method="GET" action="" class="domain-selector">
                    <label for="domainSelect"><?php echo htmlspecialchars(__('users_domain_select_label')); ?></label>
                    <input type="hidden" name="hide_system_aliases" value="<?php echo $hideSystemAliases ? '1' : '0'; ?>">
                    <select name="domain" id="domainSelect" onchange="this.form.submit()">
                        <?php foreach ($domainOptions as $domainOption): ?>
                            <option value="<?php echo htmlspecialchars($domainOption); ?>" <?php echo $domainOption === $selectedDomain ? 'selected' : ''; ?>>
                                <?php echo htmlspecialchars($domainOption); ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </form>
            <?php endif; ?>
        </div>

        <?php if (!$postfixDb): ?>
            <div class="alert alert-warning">
                <i class="fas fa-triangle-exclamation"></i>
                <?php echo htmlspecialchars(__('users_mailbox_db_unavailable')); ?>
            </div>
        <?php elseif (empty($domainOptions)): ?>
            <div class="section-card">
                <p class="domain-empty"><?php echo htmlspecialchars(__('users_domain_none_available')); ?></p>
            </div>
        <?php else: ?>
            <div class="section-card">
                <div class="section-header">
                    <h3><?php echo htmlspecialchars(__('users_mailbox_users_title')); ?></h3>
                    <?php if ($canManagePostfix): ?>
                        <button class="btn-add-user" type="button" onclick="openMailboxCreateModal()">
                            <i class="fas fa-user-plus"></i> <?php echo htmlspecialchars(__('users_mailbox_add')); ?>
                        </button>
                    <?php endif; ?>
                </div>
                <?php if (empty($mailboxes)): ?>
                    <p class="domain-empty"><?php echo htmlspecialchars(__('users_mailbox_empty')); ?></p>
                <?php else: ?>
                    <table class="mailbox-table">
                        <thead>
                            <tr>
                                <th><?php echo htmlspecialchars(__('users_mailbox_address')); ?></th>
                                <th><?php echo htmlspecialchars(__('users_mailbox_name')); ?></th>
                                <th><?php echo htmlspecialchars(__('users_mailbox_quota')); ?> (GB)</th>
                                <th><?php echo htmlspecialchars(__('users_mailbox_size')); ?></th>
                                <th><?php echo htmlspecialchars(__('status')); ?></th>
                                <?php if ($canManagePostfix): ?>
                                    <th><?php echo htmlspecialchars(__('actions')); ?></th>
                                <?php endif; ?>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($mailboxes as $mailbox): ?>
                                <tr>
                                    <td><?php echo htmlspecialchars($mailbox['username']); ?></td>
                                    <td><?php echo htmlspecialchars($mailbox['name']); ?></td>
                                    <?php $quotaGb = ($mailbox['quota'] ?? 0) / 1024; ?>
                                    <td><?php echo htmlspecialchars(number_format($quotaGb, 2)); ?> GB</td>
                                    <td class="mailbox-size">
                                        <?php echo htmlspecialchars(formatMessageSize($mailboxSizes[$mailbox['username']] ?? 0)); ?>
                                    </td>
                                    <td>
                                        <?php if ($mailbox['active']): ?>
                                            <span class="status-badge status-active">
                                                <i class="fas fa-check-circle"></i> <?php echo htmlspecialchars(__('users_active')); ?>
                                            </span>
                                        <?php else: ?>
                                            <span class="status-badge status-inactive">
                                                <i class="fas fa-times-circle"></i> <?php echo htmlspecialchars(__('users_inactive')); ?>
                                            </span>
                                        <?php endif; ?>
                                    </td>
                                    <?php if ($canManagePostfix): ?>
                                        <td class="mailbox-actions">
                                            <button class="action-btn btn-edit" onclick='openMailboxModal(<?php echo json_encode($mailbox); ?>)' title="<?php echo htmlspecialchars(__('edit')); ?>">
                                                <i class="fas fa-pen"></i>
                                            </button>
                                        </td>
                                    <?php endif; ?>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            </div>

            <div class="section-card">
                <div class="section-header">
                    <h3><?php echo htmlspecialchars(__('users_alias_title')); ?></h3>
                    <div class="section-header-actions">
                        <form method="GET" action="" class="alias-filter-form">
                            <input type="hidden" name="domain" value="<?php echo htmlspecialchars($selectedDomain); ?>">
                            <input type="hidden" name="hide_system_aliases" value="0">
                            <label class="checkbox-inline">
                                <input type="checkbox" name="hide_system_aliases" value="1" <?php echo $hideSystemAliases ? 'checked' : ''; ?> onchange="this.form.submit()">
                                <?php echo htmlspecialchars(__('users_alias_hide_system')); ?>
                            </label>
                        </form>
                        <?php if ($canManagePostfix): ?>
                            <button class="btn-add-user" type="button" onclick="openAliasCreateModal()">
                                <i class="fas fa-share"></i> <?php echo htmlspecialchars(__('users_alias_add')); ?>
                            </button>
                        <?php endif; ?>
                    </div>
                </div>
                <?php if (empty($aliases)): ?>
                    <p class="domain-empty"><?php echo htmlspecialchars(__('users_alias_empty')); ?></p>
                <?php else: ?>
                    <table class="alias-table">
                        <thead>
                            <tr>
                                <th><?php echo htmlspecialchars(__('users_alias_address')); ?></th>
                                <th><?php echo htmlspecialchars(__('users_alias_target')); ?></th>
                                <th><?php echo htmlspecialchars(__('status')); ?></th>
                                <?php if ($canManagePostfix): ?>
                                    <th><?php echo htmlspecialchars(__('actions')); ?></th>
                                <?php endif; ?>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($aliases as $alias): ?>
                                <tr>
                                    <td><?php echo htmlspecialchars($alias['address']); ?></td>
                                    <td>
                                        <span class="alias-target">
                                            <i class="fas fa-arrow-right"></i>
                                            <?php echo htmlspecialchars($alias['goto']); ?>
                                        </span>
                                    </td>
                                    <td>
                                        <?php if ($alias['active']): ?>
                                            <span class="status-badge status-active">
                                                <i class="fas fa-check-circle"></i> <?php echo htmlspecialchars(__('users_active')); ?>
                                            </span>
                                        <?php else: ?>
                                            <span class="status-badge status-inactive">
                                                <i class="fas fa-times-circle"></i> <?php echo htmlspecialchars(__('users_inactive')); ?>
                                            </span>
                                        <?php endif; ?>
                                    </td>
                                    <?php if ($canManagePostfix): ?>
                                        <td class="mailbox-actions">
                                            <button class="action-btn btn-edit" onclick='openAliasModal(<?php echo json_encode($alias); ?>)' title="<?php echo htmlspecialchars(__('edit')); ?>">
                                                <i class="fas fa-pen"></i>
                                            </button>
                                        </td>
                                    <?php endif; ?>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            </div>
        <?php endif; ?>
    </div>
  <?php endif; ?>      
</div>

<!-- Add User Modal -->
<div id="addModal" class="modal">
    <div class="modal-content">
        <div class="modal-header">
            <h2><i class="fas fa-user-plus"></i> <?php echo htmlspecialchars(__('users_add_title')); ?></h2>
            <span class="close" onclick="closeAddModal()">&times;</span>
        </div>
        <form method="POST" action="">
            <input type="hidden" name="action" value="add">
            <div class="modal-body">
                <div class="form-group">
                    <label><?php echo htmlspecialchars(__('users_username')); ?> *</label>
                    <input type="text" name="username" required>
                </div>
                <div class="form-group">
                    <label><?php echo htmlspecialchars(__('users_email')); ?> *</label>
                    <input type="text" name="email" id="addEmail" inputmode="email" autocomplete="email" required>
                    <textarea name="email" id="addEmailList" style="display:none;" disabled></textarea>
                    <small id="addEmailHint" style="display:none;"><?php echo htmlspecialchars(__('users_quarantine_email_hint')); ?></small>
                </div>
                <div class="form-group">
                    <label><?php echo htmlspecialchars(__('users_password')); ?> *</label>
                    <input type="password" name="password" required>
                </div>
                <div class="form-group">
                    <label><?php echo htmlspecialchars(__('users_role')); ?> *</label>
                    <select name="role" id="addRole" onchange="toggleRoleFields('addRole', 'addDomains', 'addEmail', 'addEmailList', 'addEmailHint')" required>
                        <option value="viewer"><?php echo htmlspecialchars($role_labels['viewer']); ?></option>
                        <option value="quarantine_user"><?php echo htmlspecialchars($role_labels['quarantine_user']); ?></option>
                        <option value="domain_admin"><?php echo htmlspecialchars($role_labels['domain_admin']); ?></option>
                        <option value="admin"><?php echo htmlspecialchars($role_labels['admin']); ?></option>
                    </select>
                </div>
                <div class="form-group" id="addDomains" style="display:none;">
                    <label><?php echo htmlspecialchars(__('users_domains_hint')); ?></label>
                    <textarea name="domains" placeholder="<?php echo htmlspecialchars(__('users_domains_placeholder')); ?>"></textarea>
                </div>
                <div class="form-group checkbox-group">
                    <input type="checkbox" name="active" id="addActive" checked>
                    <label for="addActive"><?php echo htmlspecialchars(__('users_active_account')); ?></label>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn-cancel" onclick="closeAddModal()"><?php echo htmlspecialchars(__('cancel')); ?></button>
                <button type="submit" class="btn-submit">
                    <i class="fas fa-save"></i> <?php echo htmlspecialchars(__('users_create')); ?>
                </button>
            </div>
        </form>
    </div>
</div>

<!-- Edit User Modal -->
<div id="editModal" class="modal">
    <div class="modal-content">
        <div class="modal-header">
            <h2><i class="fas fa-edit"></i> <?php echo htmlspecialchars(__('users_edit_title')); ?></h2>
            <span class="close" onclick="closeEditModal()">&times;</span>
        </div>
        <form method="POST" action="">
            <input type="hidden" name="action" value="edit">
            <input type="hidden" name="user_id" id="editUserId">
            <div class="modal-body">
                <div class="form-group">
                    <label><?php echo htmlspecialchars(__('users_username')); ?> *</label>
                    <input type="text" name="username" id="editUsername" required>
                </div>
                <div class="form-group">
                    <label><?php echo htmlspecialchars(__('users_email')); ?> *</label>
                    <input type="text" name="email" id="editEmail" inputmode="email" autocomplete="email" required>
                    <textarea name="email" id="editEmailList" style="display:none;" disabled></textarea>
                    <small id="editEmailHint" style="display:none;"><?php echo htmlspecialchars(__('users_quarantine_email_hint')); ?></small>
                </div>
                <div class="form-group">
                    <label><?php echo htmlspecialchars(__('users_new_password_hint')); ?></label>
                    <input type="password" name="password" id="editPassword">
                </div>
                <div class="form-group">
                    <label><?php echo htmlspecialchars(__('users_role')); ?> *</label>
                    <select name="role" id="editRole" onchange="toggleRoleFields('editRole', 'editDomains', 'editEmail', 'editEmailList', 'editEmailHint')" required>
                        <option value="viewer"><?php echo htmlspecialchars($role_labels['viewer']); ?></option>
                        <option value="quarantine_user"><?php echo htmlspecialchars($role_labels['quarantine_user']); ?></option>
                        <option value="domain_admin"><?php echo htmlspecialchars($role_labels['domain_admin']); ?></option>
                        <option value="admin"><?php echo htmlspecialchars($role_labels['admin']); ?></option>
                    </select>
                </div>
                <div class="form-group" id="editDomains" style="display:none;">
                    <label><?php echo htmlspecialchars(__('users_domains_hint')); ?></label>
                    <textarea name="domains" id="editDomainsText"></textarea>
                </div>
                <div class="form-group checkbox-group">
                    <input type="checkbox" name="active" id="editActive">
                    <label for="editActive"><?php echo htmlspecialchars(__('users_active_account')); ?></label>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn-cancel" onclick="closeEditModal()"><?php echo htmlspecialchars(__('cancel')); ?></button>
                <button type="submit" class="btn-submit">
                    <i class="fas fa-save"></i> <?php echo htmlspecialchars(__('users_save_changes')); ?>
                </button>
            </div>
        </form>
    </div>
</div>

<?php if ($canManagePostfix): ?>
    <!-- Create Mailbox Modal -->
    <div id="mailboxCreateModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2><i class="fas fa-user-plus"></i> <?php echo htmlspecialchars(__('users_mailbox_create_title')); ?></h2>
                <span class="close" onclick="closeMailboxCreateModal()">&times;</span>
            </div>
            <form method="POST" action="">
                <input type="hidden" name="action" value="mailbox_create">
                <input type="hidden" name="domain" value="<?php echo htmlspecialchars($selectedDomain); ?>">
                <div class="modal-body">
                    <div class="form-group">
                        <label><?php echo htmlspecialchars(__('users_mailbox_localpart')); ?> *</label>
                        <input type="text" name="mailbox_local" required>
                        <small><?php echo htmlspecialchars($selectedDomain ? '@' . $selectedDomain : ''); ?></small>
                    </div>
                    <div class="form-group">
                        <label><?php echo htmlspecialchars(__('users_mailbox_name')); ?> *</label>
                        <input type="text" name="name" required>
                    </div>
                    <div class="form-group">
                        <label><?php echo htmlspecialchars(__('users_mailbox_quota')); ?> (GB)</label>
                        <input type="number" name="quota" min="0" step="0.01" <?php echo $canEditQuota ? '' : 'readonly class="readonly-field"'; ?>>
                    </div>
                    <div class="form-group">
                        <label><?php echo htmlspecialchars(__('users_mailbox_password')); ?> *</label>
                        <input type="password" name="password" required>
                    </div>
                    <div class="form-group checkbox-group">
                        <input type="checkbox" name="active" id="mailboxCreateActive" checked>
                        <label for="mailboxCreateActive"><?php echo htmlspecialchars(__('users_active_account')); ?></label>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn-cancel" onclick="closeMailboxCreateModal()"><?php echo htmlspecialchars(__('cancel')); ?></button>
                    <button type="submit" class="btn-submit">
                        <i class="fas fa-save"></i> <?php echo htmlspecialchars(__('users_mailbox_create')); ?>
                    </button>
                </div>
            </form>
        </div>
    </div>

    <!-- Create Alias Modal -->
    <div id="aliasCreateModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2><i class="fas fa-share"></i> <?php echo htmlspecialchars(__('users_alias_create_title')); ?></h2>
                <span class="close" onclick="closeAliasCreateModal()">&times;</span>
            </div>
            <form method="POST" action="">
                <input type="hidden" name="action" value="alias_create">
                <input type="hidden" name="domain" value="<?php echo htmlspecialchars($selectedDomain); ?>">
                <div class="modal-body">
                    <div class="form-group">
                        <label><?php echo htmlspecialchars(__('users_alias_localpart')); ?> *</label>
                        <input type="text" name="alias_local" required>
                        <small><?php echo htmlspecialchars($selectedDomain ? '@' . $selectedDomain : ''); ?></small>
                    </div>
                    <div class="form-group">
                        <label><?php echo htmlspecialchars(__('users_alias_target')); ?> *</label>
                        <textarea name="goto" required></textarea>
                    </div>
                    <div class="form-group checkbox-group">
                        <input type="checkbox" name="active" id="aliasCreateActive" checked>
                        <label for="aliasCreateActive"><?php echo htmlspecialchars(__('users_active_account')); ?></label>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn-cancel" onclick="closeAliasCreateModal()"><?php echo htmlspecialchars(__('cancel')); ?></button>
                    <button type="submit" class="btn-submit">
                        <i class="fas fa-save"></i> <?php echo htmlspecialchars(__('users_alias_create')); ?>
                    </button>
                </div>
            </form>
        </div>
    </div>

    <!-- Edit Mailbox Modal -->
    <div id="mailboxModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2><i class="fas fa-envelope"></i> <?php echo htmlspecialchars(__('users_mailbox_edit_title')); ?></h2>
                <span class="close" onclick="closeMailboxModal()">&times;</span>
            </div>
            <form method="POST" action="">
                <input type="hidden" name="action" value="mailbox_update">
                <input type="hidden" name="mailbox" id="mailboxUsername">
                <input type="hidden" name="domain" id="mailboxDomain">
                <div class="modal-body">
                    <div class="form-group">
                        <label><?php echo htmlspecialchars(__('users_mailbox_address')); ?></label>
                        <input type="text" id="mailboxAddressDisplay" readonly>
                    </div>
                    <div class="form-group">
                        <label><?php echo htmlspecialchars(__('users_mailbox_name')); ?> *</label>
                        <input type="text" name="name" id="mailboxName" required>
                    </div>
                    <div class="form-group">
                        <label><?php echo htmlspecialchars(__('users_mailbox_quota')); ?> (GB)</label>
                        <input type="number" name="quota" id="mailboxQuota" min="0" step="0.01" <?php echo $canEditQuota ? '' : 'readonly class="readonly-field"'; ?>>
                    </div>
                    <div class="form-group">
                        <label><?php echo htmlspecialchars(__('users_mailbox_password')); ?></label>
                        <input type="password" name="password" id="mailboxPassword" placeholder="<?php echo htmlspecialchars(__('users_mailbox_password_hint')); ?>">
                    </div>
                    <div class="form-group checkbox-group">
                        <input type="checkbox" name="active" id="mailboxActive">
                        <label for="mailboxActive"><?php echo htmlspecialchars(__('users_active_account')); ?></label>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn-cancel" onclick="closeMailboxModal()"><?php echo htmlspecialchars(__('cancel')); ?></button>
                    <button type="submit" class="btn-submit">
                        <i class="fas fa-save"></i> <?php echo htmlspecialchars(__('users_mailbox_save')); ?>
                    </button>
                </div>
            </form>
        </div>
    </div>

    <!-- Edit Alias Modal -->
    <div id="aliasModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2><i class="fas fa-share"></i> <?php echo htmlspecialchars(__('users_alias_edit_title')); ?></h2>
                <span class="close" onclick="closeAliasModal()">&times;</span>
            </div>
            <form method="POST" action="">
                <input type="hidden" name="action" value="alias_update">
                <input type="hidden" name="address" id="aliasAddress">
                <input type="hidden" name="domain" id="aliasDomain">
                <div class="modal-body">
                    <div class="form-group">
                        <label><?php echo htmlspecialchars(__('users_alias_address')); ?></label>
                        <input type="text" id="aliasAddressDisplay" readonly>
                    </div>
                    <div class="form-group">
                        <label><?php echo htmlspecialchars(__('users_alias_target')); ?> *</label>
                        <textarea name="goto" id="aliasGoto" required></textarea>
                    </div>
                    <div class="form-group checkbox-group">
                        <input type="checkbox" name="active" id="aliasActive">
                        <label for="aliasActive"><?php echo htmlspecialchars(__('users_active_account')); ?></label>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn-cancel" onclick="closeAliasModal()"><?php echo htmlspecialchars(__('cancel')); ?></button>
                    <button type="submit" class="btn-submit">
                        <i class="fas fa-save"></i> <?php echo htmlspecialchars(__('users_alias_save')); ?>
                    </button>
                </div>
            </form>
        </div>
    </div>
<?php endif; ?>

<!-- Delete Form (hidden) -->
<form method="POST" action="" id="deleteForm">
    <input type="hidden" name="action" value="delete">
    <input type="hidden" name="user_id" id="deleteUserId">
</form>

<script>
const usersStrings = {
    deleteConfirm: <?php echo json_encode(__('users_delete_confirm')); ?>
};

function openAddModal() {
    document.getElementById('addModal').style.display = 'block';
    toggleRoleFields('addRole', 'addDomains', 'addEmail', 'addEmailList', 'addEmailHint');
}

function closeAddModal() {
    document.getElementById('addModal').style.display = 'none';
}

function openEditModal(user) {
    document.getElementById('editUserId').value = user.id;
    document.getElementById('editUsername').value = user.username;
    document.getElementById('editEmail').value = user.email;
    document.getElementById('editEmailList').value = user.email;
    document.getElementById('editRole').value = user.role;
    document.getElementById('editDomainsText').value = user.domains || '';
    document.getElementById('editActive').checked = user.active == 1;

    toggleRoleFields('editRole', 'editDomains', 'editEmail', 'editEmailList', 'editEmailHint');
    document.getElementById('editModal').style.display = 'block';
}

function closeEditModal() {
    document.getElementById('editModal').style.display = 'none';
}

function openMailboxCreateModal() {
    document.getElementById('mailboxCreateModal').style.display = 'block';
}

function closeMailboxCreateModal() {
    document.getElementById('mailboxCreateModal').style.display = 'none';
}

function openAliasCreateModal() {
    document.getElementById('aliasCreateModal').style.display = 'block';
}

function closeAliasCreateModal() {
    document.getElementById('aliasCreateModal').style.display = 'none';
}

function openMailboxModal(mailbox) {
    document.getElementById('mailboxUsername').value = mailbox.username;
    document.getElementById('mailboxDomain').value = mailbox.domain;
    document.getElementById('mailboxAddressDisplay').value = mailbox.username;
    document.getElementById('mailboxName').value = mailbox.name;
    const quotaGb = mailbox.quota ? (mailbox.quota / 1024) : 0;
    document.getElementById('mailboxQuota').value = quotaGb.toFixed(2);
    document.getElementById('mailboxPassword').value = '';
    document.getElementById('mailboxActive').checked = mailbox.active == 1;

    document.getElementById('mailboxModal').style.display = 'block';
}

function closeMailboxModal() {
    document.getElementById('mailboxModal').style.display = 'none';
}

function openAliasModal(alias) {
    document.getElementById('aliasAddress').value = alias.address;
    document.getElementById('aliasDomain').value = alias.domain;
    document.getElementById('aliasAddressDisplay').value = alias.address;
    document.getElementById('aliasGoto').value = alias.goto;
    document.getElementById('aliasActive').checked = alias.active == 1;

    document.getElementById('aliasModal').style.display = 'block';
}

function closeAliasModal() {
    document.getElementById('aliasModal').style.display = 'none';
}

function toggleRoleFields(roleId, domainsId, emailInputId, emailListId, emailHintId) {
    const role = document.getElementById(roleId).value;
    const domainsDiv = document.getElementById(domainsId);
    const emailInput = document.getElementById(emailInputId);
    const emailList = document.getElementById(emailListId);
    const emailHint = document.getElementById(emailHintId);

    if (role === 'domain_admin') {
        domainsDiv.style.display = 'block';
    } else {
        domainsDiv.style.display = 'none';
    }

    if (role === 'quarantine_user') {
        if (emailList.value.trim() === '' && emailInput.value.trim() !== '') {
            emailList.value = emailInput.value;
        }
        emailInput.style.display = 'none';
        emailInput.disabled = true;
        emailInput.required = false;
        emailList.style.display = 'block';
        emailList.disabled = false;
        emailList.required = true;
        emailHint.style.display = 'block';
    } else {
        if (emailInput.value.trim() === '' && emailList.value.trim() !== '') {
            const firstEmail = emailList.value.split(/[\s,;]+/).filter(Boolean)[0] || '';
            emailInput.value = firstEmail;
        }
        emailInput.style.display = 'block';
        emailInput.disabled = false;
        emailInput.required = true;
        emailList.style.display = 'none';
        emailList.disabled = true;
        emailList.required = false;
        emailHint.style.display = 'none';
    }
}

function confirmDelete(userId, username) {
    if (confirm(usersStrings.deleteConfirm.replace('{username}', username))) {
        document.getElementById('deleteUserId').value = userId;
        document.getElementById('deleteForm').submit();
    }
}

// Close modal when clicking outside
window.onclick = function(event) {
    const addModal = document.getElementById('addModal');
    const editModal = document.getElementById('editModal');
    const mailboxCreateModal = document.getElementById('mailboxCreateModal');
    const aliasCreateModal = document.getElementById('aliasCreateModal');
    const mailboxModal = document.getElementById('mailboxModal');
    const aliasModal = document.getElementById('aliasModal');

    if (event.target == addModal) {
        closeAddModal();
    }
    if (event.target == editModal) {
        closeEditModal();
    }
    if (event.target == mailboxCreateModal) {
        closeMailboxCreateModal();
    }
    if (event.target == aliasCreateModal) {
        closeAliasCreateModal();
    }
    if (event.target == mailboxModal) {
        closeMailboxModal();
    }
    if (event.target == aliasModal) {
        closeAliasModal();
    }
}
</script>

<?php include 'footer.php'; ?>
</body>
</html>
