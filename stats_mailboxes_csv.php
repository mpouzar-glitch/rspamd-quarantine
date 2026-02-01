<?php
/*
 * Version: 2.0.0
 * Author: Martin Pouzar
 * License: GNU General Public License v3.0
 */
// stats_mailboxes_csv.php - Export mailbox storage stats from Postfix DB to CSV

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

$errors = [];
$domainStats = getPostfixMailboxStats($errors);

if (!empty($errors)) {
    http_response_code(500);
    header('Content-Type: text/plain; charset=UTF-8');
    foreach ($errors as $error) {
        $message = $error['message'] ?? 'Unknown error.';
        echo $message . PHP_EOL;
    }
    exit;
}

$filename = sprintf('postfix-mailboxes-%s.csv', date('Ymd-His'));
header('Content-Type: text/csv; charset=UTF-8');
header('Content-Disposition: attachment; filename="' . $filename . '"');

$output = fopen('php://output', 'w');
fputcsv($output, ['Domain', 'Mailbox', 'Size']);

foreach ($domainStats as $domain) {
    foreach ($domain['mailboxes'] as $mailbox) {
        fputcsv($output, [
            $domain['domain'],
            $mailbox['name'],
            $mailbox['size'],
        ]);
    }
}

fclose($output);
