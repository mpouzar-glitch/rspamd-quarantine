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
            $email = trim($_POST['email']);
            $role = $_POST['role'];
            $domains_text = $_POST['domains'] ?? '';
            $active = isset($_POST['active']) ? 1 : 0;

            // Validate
            if (empty($username) || empty($password) || empty($email) || empty($role)) {
                $_SESSION['error_msg'] = __('users_required_fields');
                break;
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
            $email = trim($_POST['email']);
            $role = $_POST['role'];
            $domains_text = $_POST['domains'] ?? '';
            $active = isset($_POST['active']) ? 1 : 0;
            $password = $_POST['password'] ?? '';

            // Validate
            if (empty($username) || empty($email) || empty($role)) {
                $_SESSION['error_msg'] = __('users_required_fields');
                break;
            }

            // Check if username exists (except current user)
            $stmt = $db->prepare("SELECT id FROM users WHERE username = ? AND id != ?");
            $stmt->execute([$username, $user_id]);
            if ($stmt->fetch()) {
                $_SESSION['error_msg'] = __('users_username_exists');
                break;
            }

            try {
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
                logAudit($_SESSION['user_id'], $_SESSION['username'], 'user_updated', 'users', $user_id, "Updated user: $username");
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

        case 'mailbox_update':
            $mailbox = trim($_POST['mailbox'] ?? '');
            $domain = trim($_POST['domain'] ?? '');
            $name = trim($_POST['name'] ?? '');
            $quota = isset($_POST['quota']) ? max(0, (int)$_POST['quota']) : 0;
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
                $fields = [
                    'name' => $name,
                    'quota' => $quota,
                    'active' => $active,
                ];

                $sql = "UPDATE mailbox SET name = ?, quota = ?, active = ?, modified = NOW()";
                $params = [$fields['name'], $fields['quota'], $fields['active']];

                if ($password !== '') {
                    $sql .= ", password = ?";
                    $params[] = generateMd5CryptPassword($password);
                }

                $sql .= " WHERE username = ? AND domain = ?";
                $params[] = $mailbox;
                $params[] = $domain;

                $stmt = $postfixDb->prepare($sql);
                $stmt->execute($params);

                $_SESSION['success_msg'] = __('users_mailbox_update_success');
            } catch (Exception $e) {
                $_SESSION['error_msg'] = __('users_mailbox_update_error', ['error' => $e->getMessage()]);
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
} else {
    $users = [];
    $total_users = 0;
    $active_users = 0;
    $admin_count = 0;
    $domain_admin_count = 0;
}

$domainOptions = [];
$selectedDomain = '';
$mailboxes = [];
$aliases = [];

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
            SELECT address, goto, active
            FROM alias
            WHERE domain = ?
            ORDER BY address
        ");
        $stmt->execute([$selectedDomain]);
        $aliases = $stmt->fetchAll();
    }
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
                            <td><?php echo htmlspecialchars($user['email']); ?></td>
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

    <div class="domain-section">
        <div class="domain-header">
            <h2><i class="fas fa-envelope-open-text"></i> <?php echo htmlspecialchars(__('users_domain_section_title')); ?></h2>
            <?php if (!empty($domainOptions)): ?>
                <form method="GET" action="" class="domain-selector">
                    <label for="domainSelect"><?php echo htmlspecialchars(__('users_domain_select_label')); ?></label>
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
                <h3><?php echo htmlspecialchars(__('users_mailbox_users_title')); ?></h3>
                <?php if (empty($mailboxes)): ?>
                    <p class="domain-empty"><?php echo htmlspecialchars(__('users_mailbox_empty')); ?></p>
                <?php else: ?>
                    <table class="mailbox-table">
                        <thead>
                            <tr>
                                <th><?php echo htmlspecialchars(__('users_mailbox_address')); ?></th>
                                <th><?php echo htmlspecialchars(__('users_mailbox_name')); ?></th>
                                <th><?php echo htmlspecialchars(__('users_mailbox_quota')); ?></th>
                                <th><?php echo htmlspecialchars(__('users_mailbox_size')); ?></th>
                                <th><?php echo htmlspecialchars(__('status')); ?></th>
                                <th><?php echo htmlspecialchars(__('actions')); ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($mailboxes as $mailbox): ?>
                                <tr>
                                    <td><?php echo htmlspecialchars($mailbox['username']); ?></td>
                                    <td><?php echo htmlspecialchars($mailbox['name']); ?></td>
                                    <td><?php echo htmlspecialchars(number_format((int)$mailbox['quota'])); ?></td>
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
                                    <td class="mailbox-actions">
                                        <button class="action-btn btn-edit" onclick='openMailboxModal(<?php echo json_encode($mailbox); ?>)' title="<?php echo htmlspecialchars(__('edit')); ?>">
                                            <i class="fas fa-pen"></i>
                                        </button>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            </div>

            <div class="section-card">
                <h3><?php echo htmlspecialchars(__('users_alias_title')); ?></h3>
                <?php if (empty($aliases)): ?>
                    <p class="domain-empty"><?php echo htmlspecialchars(__('users_alias_empty')); ?></p>
                <?php else: ?>
                    <table class="alias-table">
                        <thead>
                            <tr>
                                <th><?php echo htmlspecialchars(__('users_alias_address')); ?></th>
                                <th><?php echo htmlspecialchars(__('users_alias_target')); ?></th>
                                <th><?php echo htmlspecialchars(__('status')); ?></th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($aliases as $alias): ?>
                                <tr>
                                    <td><?php echo htmlspecialchars($alias['address']); ?></td>
                                    <td><?php echo htmlspecialchars($alias['goto']); ?></td>
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
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            </div>
        <?php endif; ?>
    </div>
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
                    <input type="email" name="email" required>
                </div>
                <div class="form-group">
                    <label><?php echo htmlspecialchars(__('users_password')); ?> *</label>
                    <input type="password" name="password" required>
                </div>
                <div class="form-group">
                    <label><?php echo htmlspecialchars(__('users_role')); ?> *</label>
                    <select name="role" id="addRole" onchange="toggleDomains('addRole', 'addDomains')" required>
                        <option value="viewer"><?php echo htmlspecialchars($role_labels['viewer']); ?></option>
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
                    <input type="email" name="email" id="editEmail" required>
                </div>
                <div class="form-group">
                    <label><?php echo htmlspecialchars(__('users_new_password_hint')); ?></label>
                    <input type="password" name="password" id="editPassword">
                </div>
                <div class="form-group">
                    <label><?php echo htmlspecialchars(__('users_role')); ?> *</label>
                    <select name="role" id="editRole" onchange="toggleDomains('editRole', 'editDomains')" required>
                        <option value="viewer"><?php echo htmlspecialchars($role_labels['viewer']); ?></option>
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
                    <label><?php echo htmlspecialchars(__('users_mailbox_quota')); ?></label>
                    <input type="number" name="quota" id="mailboxQuota" min="0">
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
}

function closeAddModal() {
    document.getElementById('addModal').style.display = 'none';
}

function openEditModal(user) {
    document.getElementById('editUserId').value = user.id;
    document.getElementById('editUsername').value = user.username;
    document.getElementById('editEmail').value = user.email;
    document.getElementById('editRole').value = user.role;
    document.getElementById('editDomainsText').value = user.domains || '';
    document.getElementById('editActive').checked = user.active == 1;

    toggleDomains('editRole', 'editDomains');
    document.getElementById('editModal').style.display = 'block';
}

function closeEditModal() {
    document.getElementById('editModal').style.display = 'none';
}

function openMailboxModal(mailbox) {
    document.getElementById('mailboxUsername').value = mailbox.username;
    document.getElementById('mailboxDomain').value = mailbox.domain;
    document.getElementById('mailboxAddressDisplay').value = mailbox.username;
    document.getElementById('mailboxName').value = mailbox.name;
    document.getElementById('mailboxQuota').value = mailbox.quota;
    document.getElementById('mailboxPassword').value = '';
    document.getElementById('mailboxActive').checked = mailbox.active == 1;

    document.getElementById('mailboxModal').style.display = 'block';
}

function closeMailboxModal() {
    document.getElementById('mailboxModal').style.display = 'none';
}

function toggleDomains(roleId, domainsId) {
    const role = document.getElementById(roleId).value;
    const domainsDiv = document.getElementById(domainsId);

    if (role === 'domain_admin') {
        domainsDiv.style.display = 'block';
    } else {
        domainsDiv.style.display = 'none';
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
    const mailboxModal = document.getElementById('mailboxModal');

    if (event.target == addModal) {
        closeAddModal();
    }
    if (event.target == editModal) {
        closeEditModal();
    }
    if (event.target == mailboxModal) {
        closeMailboxModal();
    }
}
</script>

<?php include 'footer.php'; ?>
</body>
</html>
