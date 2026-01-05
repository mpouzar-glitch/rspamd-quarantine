<?php
/*
 * Version: 2.0.0
 * Author: Martin Pouzar
 * License: GNU General Public License v3.0
 */
/**
 * Process Bulk Operations
 * Converts bulk_operations.php format to operations.php format
 */

session_start();
require_once 'config.php';
require_once 'functions.php';

// Authentication check
if (!isAuthenticated()) {
    header('Location: login.php');
    exit;
}

// Permission check
if (!checkPermission('domain_admin')) {
    $_SESSION['error_msg'] = 'Nemáte oprávnění pro hromadné operace.';
    header('Location: bulk_operations.php');
    exit;
}

// Process form data
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    $_SESSION['error_msg'] = 'Neplatný požadavek';
    header('Location: bulk_operations.php');
    exit;
}

// Collect operations from form
$operations = [];
$release_ids = [];

// Process all POST data
foreach ($_POST as $key => $value) {
    // Radio button actions (action_123 = 'spam'|'ham'|'forget')
    if (preg_match('/^action_(\d+)$/', $key, $matches)) {
        $msg_id = (int)$matches[1];
        $action = $value;

        if (in_array($action, ['spam', 'ham', 'forget'])) {
            $operations[$msg_id] = $action;
        }
    }

    // Checkbox releases (release_123 = '1')
    if (preg_match('/^release_(\d+)$/', $key, $matches) && $value == '1') {
        $release_ids[] = (int)$matches[1];
    }
}

// Validate we have at least some operations
if (empty($operations) && empty($release_ids)) {
    $_SESSION['error_msg'] = 'Nevybrali jste žádné operace';
    header('Location: bulk_operations.php');
    exit;
}

// Prepare operations for operations.php format
$learn_spam_ids = [];
$learn_ham_ids = [];
$forget_ids = [];

foreach ($operations as $msg_id => $action) {
    switch ($action) {
        case 'spam':
            $learn_spam_ids[] = $msg_id;
            break;
        case 'ham':
            $learn_ham_ids[] = $msg_id;
            break;
        case 'forget':
            $forget_ids[] = $msg_id;
            break;
    }
}

// Process each operation type
$total_processed = 0;
$success_messages = [];
$error_messages = [];
define('BULK_PROCESSING_MODE', true);

// 1. Learn SPAM
if (!empty($learn_spam_ids)) {
    $_POST['operation'] = 'learn_spam';
    $_POST['message_ids'] = implode(',', $learn_spam_ids);
    $_POST['return_url'] = 'bulk_operations.php';

    ob_start();
    include 'operations.php';
    ob_end_clean();

    if (isset($_SESSION['success_msg'])) {
        $success_messages[] = $_SESSION['success_msg'];
        unset($_SESSION['success_msg']);
    }
    if (isset($_SESSION['error_msg'])) {
        $error_messages[] = $_SESSION['error_msg'];
        unset($_SESSION['error_msg']);
    }
    if (isset($_SESSION['warning_msg'])) {
        $error_messages[] = $_SESSION['warning_msg'];
        unset($_SESSION['warning_msg']);
    }

    $total_processed += count($learn_spam_ids);
}

// 2. Learn HAM
if (!empty($learn_ham_ids)) {
    $_POST['operation'] = 'learn_ham';
    $_POST['message_ids'] = implode(',', $learn_ham_ids);
    $_POST['return_url'] = 'bulk_operations.php';

    ob_start();
    include 'operations.php';
    ob_end_clean();

    if (isset($_SESSION['success_msg'])) {
        $success_messages[] = $_SESSION['success_msg'];
        unset($_SESSION['success_msg']);
    }
    if (isset($_SESSION['error_msg'])) {
        $error_messages[] = $_SESSION['error_msg'];
        unset($_SESSION['error_msg']);
    }
    if (isset($_SESSION['warning_msg'])) {
        $error_messages[] = $_SESSION['warning_msg'];
        unset($_SESSION['warning_msg']);
    }

    $total_processed += count($learn_ham_ids);
}

// 3. Forget (if implemented in operations.php)
if (!empty($forget_ids)) {
    // Note: operations.php may not have 'forget' operation
    // You may need to implement this or handle differently
    $error_messages[] = "Operace 'Zapomenout' není zatím implementována pro " . count($forget_ids) . " zpráv";
}

// 4. Release
if (!empty($release_ids)) {
    $_POST['operation'] = 'release';
    $_POST['message_ids'] = implode(',', $release_ids);
    $_POST['return_url'] = 'bulk_operations.php';

    ob_start();
    include 'operations.php';
    ob_end_clean();

    if (isset($_SESSION['success_msg'])) {
        $success_messages[] = $_SESSION['success_msg'];
        unset($_SESSION['success_msg']);
    }
    if (isset($_SESSION['error_msg'])) {
        $error_messages[] = $_SESSION['error_msg'];
        unset($_SESSION['error_msg']);
    }
    if (isset($_SESSION['warning_msg'])) {
        $error_messages[] = $_SESSION['warning_msg'];
        unset($_SESSION['warning_msg']);
    }

    $total_processed += count($release_ids);
}

// Set final messages
if (!empty($success_messages)) {
    $_SESSION['success_msg'] = implode(' | ', $success_messages);
}

if (!empty($error_messages)) {
    $_SESSION['warning_msg'] = implode(' | ', $error_messages);
}

if (empty($success_messages) && empty($error_messages)) {
    $_SESSION['info_msg'] = "Zpracováno $total_processed operací";
}

// Redirect back
header('Location: bulk_operations.php');
exit;
