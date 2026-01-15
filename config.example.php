<?php
/**
 * Rspamd Quarantine - Configuration File
 * Version: 2.0.2
 * Updated: 2026-01-01
 * 
 * OPRAVENO: Session warnings, duplicitní konstanty
 */

// ============================================
// Error Reporting & Logging
// ============================================
error_reporting(E_ALL);
ini_set('display_errors', 0);  // Set to 1 for development
ini_set('log_errors', 1);
ini_set('error_log', '/var/log/rspamd_quarantine_errors.log');

// ============================================
// Session Configuration (BEFORE session_start!)
// ============================================
if (session_status() === PHP_SESSION_NONE) {
    ini_set('session.cookie_httponly', 1);
    ini_set('session.cookie_secure', 0);  // Set to 1 if using HTTPS only
    ini_set('session.use_strict_mode', 1);
    ini_set('session.gc_maxlifetime', 3600);
    ini_set('session.cookie_samesite', 'Strict');
    session_start();
}

// ============================================
// LIST OF IP ADDRESS RSPAMD SERVERS
// ============================================
define('RECEIVER_ALLOWED_IPS', [
    '127.0.0.1',           // Localhost
    '::1',                 // IPv6 localhost
    '192.168.0.1',   
 ]);

// ============================================
// Debug Mode
// ============================================
if (!defined('DEBUG_MODE')) {
    define('DEBUG_MODE', false);  // Set to true for troubleshooting
}

// ============================================================================
// AUTO-LEARN CONFIGURATION
// ============================================================================

// Enable/disable auto-learn feature in bulk operations
// When enabled, messages with score >= AUTOLEARN_SCORE will be automatically
// marked for learning as SPAM
define('AUTOLEARN_ENABLED', true);

// Score threshold for auto-learning as SPAM
// Messages in quarantine (state=0) with score >= this value will be
// automatically selected for SPAM learning
define('AUTOLEARN_SCORE', 15.0);

// ============================================
// Database Configuration
// ============================================
if (!defined('DB_HOST')) {
    define('DB_HOST', 'localhost');
    define('DB_NAME', 'rspamd_quarantine');
    define('DB_USER', 'rspamd_quarantine');
    define('DB_PASS', 'set password secure');  
    define('DB_CHARSET', 'utf8mb4');
}

// Security - použít databázové uživatele
define('AUTH_ENABLED', true);
define('USE_DATABASE_AUTH', true); // Nové: použít DB auth místo statického

// ============================================
// IMAP Authentication (fallback for email usernames)
// ============================================
define('IMAP_AUTH_ENABLED', false);
define('IMAP_SERVER', 'mail.example.com');
define('IMAP_PORT', 993);
define('IMAP_SECURITY', 'ssl'); // ssl, tls, or none
define('IMAP_VALIDATE_CERT', true);

// ============================================
// Application Settings
// ============================================
if (!defined('APP_NAME')) {
    define('APP_NAME', 'Rspamd Quarantine');
    define('APP_VERSION', '2.0.2');
    define('ITEMS_PER_PAGE', 50);
    define('APP_TIMEZONE', 'Europe/Prague');
}

// Set timezone
date_default_timezone_set(APP_TIMEZONE);

// ============================================
// Rspamd API Configuration
// ============================================
if (!defined('RSPAMD_API_URL')) {
    define('RSPAMD_API_URL', 'http://127.0.0.1:11334');
    define('RSPAMD_API_PASSWORD', '');  // Empty if no password
}

// ============================================
// Message Release Configuration
// ============================================
if (!defined('RELEASE_COMMAND')) {
    define('RELEASE_COMMAND', '/usr/local/bin/rspamd_release.sh');
}

// ============================================
// Security Settings
// ============================================
if (!defined('SESSION_TIMEOUT')) {
    define('SESSION_TIMEOUT', 3600);        // 1 hour
    define('PASSWORD_MIN_LENGTH', 8);
    define('MAX_LOGIN_ATTEMPTS', 5);
    define('LOGIN_TIMEOUT', 300);           // 5 minutes lockout
}

// ============================================
// Data Retention Settings
// ============================================
if (!defined('QUARANTINE_RETENTION_DAYS')) {
    define('QUARANTINE_RETENTION_DAYS', 30);
    define('TRACE_RETENTION_DAYS', 90);
    define('AUDIT_RETENTION_DAYS', 365);
}

// ============================================
// Database Connection Class (Singleton)
// ============================================
if (!class_exists('Database')) {
    class Database {
        private static $instance = null;
        private $connection;

        private function __construct() {
            try {
                $dsn = sprintf(
                    'mysql:host=%s;dbname=%s;charset=%s',
                    DB_HOST,
                    DB_NAME,
                    DB_CHARSET
                );

                $options = [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    PDO::ATTR_EMULATE_PREPARES => false,
                    PDO::MYSQL_ATTR_INIT_COMMAND => 'SET NAMES ' . DB_CHARSET
                ];

                $this->connection = new PDO($dsn, DB_USER, DB_PASS, $options);

            } catch (PDOException $e) {
                error_log('Database connection failed: ' . $e->getMessage());
                die('Database connection failed. Please check logs for details.');
            }
        }

        public static function getInstance() {
            if (self::$instance === null) {
                self::$instance = new Database();
            }
            return self::$instance;
        }

        public function getConnection() {
            return $this->connection;
        }

        // Prevent cloning
        private function __clone() {}

        // Prevent unserialization
        public function __wakeup() {
            throw new Exception('Cannot unserialize singleton');
        }
    }
}

// ============================================
// Load Helper Functions
// ============================================
$functions_file = __DIR__ . '/functions.php';
if (file_exists($functions_file)) {
    require_once $functions_file;
} else {
    error_log('Critical error: functions.php not found in ' . __DIR__);
    die('Critical error: functions.php not found!');
}

// ============================================
// Session Timeout Check
// ============================================
if (function_exists('isAuthenticated') && isAuthenticated()) {
    $last_activity = $_SESSION['last_activity'] ?? time();
    if (time() - $last_activity > SESSION_TIMEOUT) {
        session_unset();
        session_destroy();
        header('Location: login.php?timeout=1');
        exit;
    }
    $_SESSION['last_activity'] = time();
}

// ============================================
// Debug Output (if enabled)
// ============================================
if (DEBUG_MODE && function_exists('isAuthenticated') && isAuthenticated() && isset($_GET['debug_domain'])) {
    debugDomainFilter();
}

?>
