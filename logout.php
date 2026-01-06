<?php
require_once __DIR__ . '/config.php';
session_start();

// Log logout action if the user is authenticated
if (isAuthenticated()) {
    logAudit(
        $_SESSION['user_id'] ?? null,
        $_SESSION['username'] ?? 'unknown',
        'logout',
        'session',
        null,
        'User logged out'
    );
}

session_destroy();
header('Location: login.php?logout=1');
?>
