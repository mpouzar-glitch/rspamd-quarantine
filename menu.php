<?php
/*
 * Version: 2.0.0
 * Author: Martin Pouzar
 * License: GNU General Public License v3.0
 */
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/lang_helper.php';
// menu.php - Shared navigation for all pages
if (!isset($_SESSION['authenticated'])) {
    header('Location: login.php');
    exit;
}

$user_role = $_SESSION['user_role'] ?? 'viewer';
$username = $_SESSION['username'] ?? 'Unknown';
$current_page = basename($_SERVER['PHP_SELF']);
$page_title = $page_title ?? ($pageTitle ?? __('app_title'));

$role_labels = [
    'admin' => __('role_admin'),
    'domain_admin' => __('role_domain_admin'),
    'quarantine_user' => __('role_quarantine_user'),
    'viewer' => __('role_viewer'),
];
$user_role_label = $role_labels[$user_role] ?? $user_role;

// Get number of quarantined messages for the badge
try {
    $db = Database::getInstance()->getConnection();
    $params = [];
    $domain_filter = getDomainFilterSQL($params);

    $stmt = $db->prepare("SELECT COUNT(*) FROM quarantine_messages WHERE state = 0 AND $domain_filter");
    $stmt->execute($params);
    $quarantine_count = $stmt->fetchColumn();
} catch (Exception $e) {
    $quarantine_count = 0;
}
?>
<!DOCTYPE html>
<html lang="<?php echo htmlspecialchars(currentLang()); ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($page_title) ?></title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <link rel="stylesheet" href="css/style.css">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: #f5f5f5;
            padding-top: 70px;
        }

        .top-nav {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 0;
            box-shadow: 0 2px 10px rgba(0,0,0,0.3);
            z-index: 1000;
            height: 60px;
        }

        .nav-container {
            max-width: 1600px;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
            height: 100%;
            padding: 0 20px;
        }

        .nav-brand {
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 20px;
            font-weight: bold;
            flex-shrink: 0;
        }

        .nav-brand i {
            font-size: 24px;
            color: #3498db;
        }

        .nav-menu {
            display: flex;
            gap: 5px;
            align-items: center;
        }

        .nav-item {
            color: white;
            text-decoration: none;
            padding: 18px 16px;
            display: flex;
            align-items: center;
            gap: 8px;
            transition: all 0.3s;
            font-size: 14px;
            position: relative;
            height: 60px;
            white-space: nowrap;
        }

        .nav-item:hover {
            background: rgba(255,255,255,0.1);
        }

        .nav-item.active {
            background: rgba(52, 152, 219, 0.3);
            border-bottom: 3px solid #3498db;
        }

        .nav-item i {
            font-size: 16px;
        }

        .badge-count {
            background: #e74c3c;
            color: white;
            padding: 2px 6px;
            border-radius: 10px;
            font-size: 11px;
            font-weight: bold;
            margin-left: 4px;
        }

        .nav-user {
            display: flex;
            align-items: center;
            gap: 15px;
            padding-left: 15px;
            border-left: 1px solid rgba(255,255,255,0.2);
            flex-shrink: 0;
        }

        .user-info {
            display: flex;
            flex-direction: column;
            align-items: flex-end;
        }

        .user-name {
            font-weight: 600;
            font-size: 13px;
        }

        .user-role {
            font-size: 11px;
            opacity: 0.8;
            color: #3498db;
        }

        /* Hamburger menu button */
        .menu-toggle {
            display: none;
            background: none;
            border: none;
            color: white;
            font-size: 24px;
            cursor: pointer;
            padding: 10px;
            margin-left: auto;
        }

        .domain-filter-info {
            position: fixed;
            top: 60px;
            left: 0;
            right: 0;
            background: #f39c12;
            color: white;
            padding: 8px 20px;
            text-align: center;
            font-size: 12px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            z-index: 999;
        }

        .has-domain-filter {
            padding-top: 100px;
        }

        .container {
            max-width: 1600px;
            margin: 0 auto;
            padding: 20px;
        }

        .alert {
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 4px;
        }
        .alert-success {
            background: #d4edda;
            color: #155724;
            border-left: 4px solid #28a745;
        }
        .alert-error {
            background: #f8d7da;
            color: #721c24;
            border-left: 4px solid #dc3545;
        }

        /* Tablet responsiveness */
        @media (max-width: 1024px) {
            .nav-item span {
                display: none;
            }
            .nav-item {
                padding: 18px 12px;
            }
            .nav-brand span {
                font-size: 16px;
            }
        }

        /* Mobile responsiveness */
        @media (max-width: 768px) {
            body {
                padding-top: 60px;
            }

            .has-domain-filter {
                padding-top: 95px;
            }

            .nav-brand span {
                display: none;
            }

            .nav-brand {
                font-size: 24px;
            }

            .menu-toggle {
                display: block;
            }

            .nav-menu {
                position: fixed;
                top: 60px;
                left: 0;
                right: 0;
                background: #2c3e50;
                flex-direction: column;
                gap: 0;
                padding: 0;
                max-height: 0;
                overflow: hidden;
                transition: max-height 0.3s ease-in-out;
                box-shadow: 0 5px 10px rgba(0,0,0,0.3);
            }

            .nav-menu.active {
                max-height: calc(100vh - 60px);
                overflow-y: auto;
            }

            .nav-item {
                width: 100%;
                height: auto;
                padding: 15px 20px;
                border-bottom: 1px solid rgba(255,255,255,0.1);
                justify-content: flex-start;
            }

            .nav-item span {
                display: inline;
            }

            .nav-item.active {
                border-bottom: 1px solid rgba(255,255,255,0.1);
                border-left: 4px solid #3498db;
            }

            .nav-user {
                padding: 15px 20px;
                border-left: none;
                border-top: 2px solid rgba(255,255,255,0.2);
                justify-content: space-between;
                width: 100%;
            }

            .user-info {
                display: flex;
                align-items: flex-start;
            }

            .domain-filter-info {
                top: 60px;
                padding: 6px 15px;
                font-size: 11px;
            }

            .container {
                padding: 15px;
            }
        }

        @media (max-width: 480px) {
            .nav-brand i {
                font-size: 20px;
            }

            .nav-item {
                padding: 12px 15px;
                font-size: 13px;
            }

            .nav-item i {
                font-size: 14px;
            }

            .container {
                padding: 10px;
            }
        }
    </style>
</head>
<body<?= ($user_role === 'domain_admin' && !empty($_SESSION['allowed_domains'])) ? ' class="has-domain-filter"' : '' ?>>

<nav class="top-nav">
    <div class="nav-container">
        <div class="nav-brand">
            <i class="fas fa-envelope-circle-check"></i>
            <span><?php echo htmlspecialchars(__('app_title')); ?></span>
        </div>

        <button class="menu-toggle" id="menuToggle" aria-label="<?php echo htmlspecialchars(__('menu_toggle')); ?>">
            <i class="fas fa-bars"></i>
        </button>

        <div class="nav-menu" id="navMenu">
            <a href="index.php?reset_page=1" class="nav-item <?= $current_page === 'index.php' ? 'active' : '' ?>">
                <i class="fas fa-inbox"></i>
                <span><?php echo htmlspecialchars(__('nav_quarantine')); ?></span>
                <?php if ($quarantine_count > 0): ?>
                    <span class="badge-count"><?= $quarantine_count ?></span>
                <?php endif; ?>
            </a>

            <?php if (checkPermission('domain_admin')): ?>            
                <a href="bulk_operations.php?reset_page=1" class="nav-item <?= $current_page === 'bulk_operations.php' ? 'active' : '' ?>">
                    <i class="fas fa-tasks"></i>
                    <span><?php echo htmlspecialchars(__('nav_bulk_operations')); ?></span>
                </a>
            <?php endif; ?>

            <a href="trace.php?reset_page=1" class="nav-item <?= $current_page === 'trace.php' ? 'active' : '' ?>">
                <i class="fas fa-search"></i>
                <span><?php echo htmlspecialchars(__('nav_trace')); ?></span>
            </a>

            <?php if (checkPermission('domain_admin')): ?>
                <a href="audit.php" class="nav-item <?= $current_page === 'audit.php' ? 'active' : '' ?>">
                    <i class="fas fa-clipboard-list"></i>
                    <span><?php echo htmlspecialchars(__('nav_audit')); ?></span>
                </a>
            <?php endif; ?>

            <a href="stats.php" class="nav-item <?= $current_page === 'stats.php' ? 'active' : '' ?>">
                <i class="fas fa-chart-bar"></i>
                <span><?php echo htmlspecialchars(__('nav_statistics')); ?></span>
            </a>

            <?php if (checkPermission('domain_admin')): ?>
                <a href="maps.php" class="nav-item <?= $current_page === 'maps.php' ? 'active' : '' ?>">
                    <i class="fas fa-list-check"></i>
                    <span><?php echo htmlspecialchars(__('nav_maps')); ?></span>
                </a>
            <?php endif; ?>

            <?php if (checkPermission('domain_admin')): ?>
                <a href="users.php" class="nav-item <?= $current_page === 'users.php' ? 'active' : '' ?>">
                    <i class="fas fa-users-cog"></i>
                    <span><?php echo htmlspecialchars(__('nav_users')); ?></span>
                </a>
            <?php endif; ?>

            <?php if (checkPermission('admin')): ?>
                <a href="service_health.php" class="nav-item <?= $current_page === 'service_health.php' ? 'active' : '' ?>">
                    <i class="fas fa-heart-pulse"></i>
                </a>
            <?php endif; ?>

            <a href="logout.php" class="nav-item">
                <i class="fas fa-sign-out-alt"></i>
            </a>

            <div class="nav-user">
                <div class="user-info">
                    <div class="user-name"><?= htmlspecialchars($username) ?></div>
                    <div class="user-role"><?= htmlspecialchars($user_role_label) ?></div>
                </div>
            </div>
        </div>
    </div>
</nav>

<?php if ($user_role === 'domain_admin' && !empty($_SESSION['allowed_domains'])): ?>
    <div class="domain-filter-info">
        <i class="fas fa-filter"></i> 
        <strong><?php echo htmlspecialchars(__('domain_filter_info')); ?></strong>
        <?= htmlspecialchars(implode(', ', $_SESSION['allowed_domains'])) ?>
    </div>
<?php endif; ?>

<div class="container">
<?php if (isset($_SESSION['success_msg'])): ?>
    <div class="alert alert-success">
        <i class="fas fa-check-circle"></i> <?= htmlspecialchars($_SESSION['success_msg']) ?>
    </div>
    <?php unset($_SESSION['success_msg']); ?>
<?php endif; ?>

<?php if (isset($_SESSION['error_msg'])): ?>
    <div class="alert alert-error">
        <i class="fas fa-exclamation-circle"></i> <?= htmlspecialchars($_SESSION['error_msg']) ?>
    </div>
    <?php unset($_SESSION['error_msg']); ?>
<?php endif; ?>

<script>
document.addEventListener('DOMContentLoaded', function() {
    const menuToggle = document.getElementById('menuToggle');
    const navMenu = document.getElementById('navMenu');

    menuToggle.addEventListener('click', function() {
        navMenu.classList.toggle('active');
        const icon = this.querySelector('i');
        icon.classList.toggle('fa-bars');
        icon.classList.toggle('fa-times');
    });

    // Close menu when clicking on a link
    const navLinks = navMenu.querySelectorAll('.nav-item');
    navLinks.forEach(link => {
        link.addEventListener('click', function() {
            if (window.innerWidth <= 768) {
                navMenu.classList.remove('active');
                const icon = menuToggle.querySelector('i');
                icon.classList.add('fa-bars');
                icon.classList.remove('fa-times');
            }
        });
    });

    // Close menu when clicking outside
    document.addEventListener('click', function(event) {
        if (window.innerWidth <= 768) {
            const isClickInside = navMenu.contains(event.target) || menuToggle.contains(event.target);
            if (!isClickInside && navMenu.classList.contains('active')) {
                navMenu.classList.remove('active');
                const icon = menuToggle.querySelector('i');
                icon.classList.add('fa-bars');
                icon.classList.remove('fa-times');
            }
        }
    });
});
</script>
