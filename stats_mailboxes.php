<?php
/*
 * Version: 2.0.0
 * Author: Martin Pouzar
 * License: GNU General Public License v3.0
 */
// stats_mailboxes.php - Mailbox storage statistics for admins

session_start();
require_once 'config.php';
require_once 'functions.php';
require_once 'lang_helper.php';

// Check authentication
if (!isAuthenticated()) {
    header('Location: login.php');
    exit;
}

$userRole = $_SESSION['user_role'] ?? 'viewer';
if ($userRole !== 'admin') {
    $_SESSION['error_msg'] = __('stats_mailboxes_admin_only');
    header('Location: stats.php');
    exit;
}

$baseMailDir = defined('VMAIL_BASE_DIR') ? VMAIL_BASE_DIR : '/var/vmail/vmail1';
$errors = [];
$domainStats = getMailboxStorageStats($baseMailDir, $errors);

$page_title = __('stats_mailboxes_page_title', ['app' => __('app_title')]);
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
    <link rel="stylesheet" href="css/stats.css">
</head>
<body>
    <div class="stats-container">
        <div class="header-with-stats">
            <div class="header-title">
                <h1><i class="fas fa-hard-drive"></i> <?php echo htmlspecialchars(__('stats_mailboxes_title')); ?></h1>
            </div>
        </div>

        <div class="stats-subnav">
            <a href="stats.php">
                <i class="fas fa-chart-bar"></i> <?php echo htmlspecialchars(__('stats_subnav_overview')); ?>
            </a>
            <a href="symbol_search.php">
                <i class="fas fa-magnifying-glass-chart"></i> <?php echo htmlspecialchars(__('stats_subnav_symbol_search')); ?>
            </a>
            <a href="stats_mailboxes.php" class="active">
                <i class="fas fa-hard-drive"></i> <?php echo htmlspecialchars(__('stats_subnav_mailboxes')); ?>
            </a>
        </div>

        <?php displayAlerts(); ?>

        <div class="mailbox-summary">
            <i class="fas fa-folder-tree"></i>
            <?php echo htmlspecialchars(__('stats_mailboxes_base_path', ['path' => $baseMailDir])); ?>
        </div>

        <?php if (!empty($errors)): ?>
            <div class="alert alert-warning">
                <i class="fas fa-triangle-exclamation"></i>
                <ul class="mailbox-errors">
                    <?php foreach ($errors as $error): ?>
                        <li>
                            <?php if ($error['type'] === 'base'): ?>
                                <?php echo htmlspecialchars(__('stats_mailboxes_error_base', ['path' => $error['path']])); ?>
                            <?php elseif ($error['type'] === 'domain'): ?>
                                <?php echo htmlspecialchars(__('stats_mailboxes_error_domain', ['domain' => $error['domain']])); ?>
                            <?php else: ?>
                                <?php echo htmlspecialchars(__('stats_mailboxes_error_mailbox', [
                                    'domain' => $error['domain'],
                                    'mailbox' => $error['mailbox'],
                                ])); ?>
                            <?php endif; ?>
                        </li>
                    <?php endforeach; ?>
                </ul>
            </div>
        <?php endif; ?>

        <?php if (empty($domainStats)): ?>
            <div class="empty-state">
                <i class="fas fa-inbox"></i>
                <p><?php echo htmlspecialchars(__('stats_mailboxes_empty')); ?></p>
            </div>
        <?php else: ?>
            <div class="mailbox-tree">
                <?php foreach ($domainStats as $domain): ?>
                    <div class="domain-card">
                        <div class="domain-header">
                            <div class="domain-title">
                                <i class="fas fa-globe"></i>
                                <span><?php echo htmlspecialchars($domain['domain']); ?></span>
                            </div>
                            <div class="domain-meta">
                                <?php echo htmlspecialchars(__(
                                    'stats_mailboxes_domain_meta',
                                    [
                                        'count' => number_format($domain['mailbox_count']),
                                        'size' => formatMessageSize($domain['total_size']),
                                    ]
                                )); ?>
                            </div>
                        </div>
                        <ul class="mailbox-list">
                            <?php foreach ($domain['mailboxes'] as $mailbox): ?>
                                <li>
                                    <span class="mailbox-name">
                                        <i class="fas fa-envelope"></i>
                                        <?php echo htmlspecialchars($mailbox['name']); ?>
                                    </span>
                                    <span class="mailbox-size">
                                        <?php echo htmlspecialchars(formatMessageSize($mailbox['size'])); ?>
                                    </span>
                                </li>
                            <?php endforeach; ?>
                        </ul>
                    </div>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>
    </div>
</body>
</html>
