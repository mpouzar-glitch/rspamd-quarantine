<?php
/**
 * Rspamd Quarantine - User Management
 * Version: 2.0.4
 * Updated: Full UI refresh and working domain assignments
 */

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/lang_helper.php';
requireAuth();

if (!checkPermission('admin')) {
    $_SESSION['error_msg'] = __('users_access_denied');
    header('Location: index.php');
    exit;
}

$db = Database::getInstance()->getConnection();

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    switch ($action) {
        case 'add':
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
    }

    header('Location: users.php');
    exit;
}

// Get all users with their domains (one per line)
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

    <?php displayAlerts(); ?>

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
                                    <?php echo htmlspecialchars(str_replace("
", ", ", $user['domains'])); ?>
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

    if (event.target == addModal) {
        closeAddModal();
    }
    if (event.target == editModal) {
        closeEditModal();
    }
}
</script>

<?php include 'footer.php'; ?>
</body>
</html>
