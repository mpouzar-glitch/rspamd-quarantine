<?php
/*
 * Rspamd Quarantine - Helper Functions
 * Version: 2.0.0
 * Author: Martin Pouzar
 * License: GNU General Public License v3.0
 * 
 * Authentication, authorization, audit logging, and utility functions
 */

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

function getPostfixConnection(?string &$error = null): ?PDO {
    static $connection = null;

    if ($connection instanceof PDO) {
        return $connection;
    }

    if (!defined('POSTFIX_DB_HOST') || !defined('POSTFIX_DB_NAME') || !defined('POSTFIX_DB_USER')) {
        $error = 'Postfix database configuration missing.';
        return null;
    }

    $charset = defined('POSTFIX_DB_CHARSET') ? POSTFIX_DB_CHARSET : 'utf8mb4';

    try {
        $dsn = sprintf(
            'mysql:host=%s;dbname=%s;charset=%s',
            POSTFIX_DB_HOST,
            POSTFIX_DB_NAME,
            $charset
        );

        $options = [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
            PDO::MYSQL_ATTR_INIT_COMMAND => 'SET NAMES ' . $charset
        ];

        $password = defined('POSTFIX_DB_PASS') ? POSTFIX_DB_PASS : '';
        $connection = new PDO($dsn, POSTFIX_DB_USER, $password, $options);
    } catch (PDOException $e) {
        $error = $e->getMessage();
        return null;
    }

    return $connection;
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

// PHP 8.4 null safety helpers
if (!function_exists('safe_strtotime')) {
    function safe_strtotime($datetime) {
        return $datetime ? strtotime($datetime) : time();
    }
}

if (!function_exists('safe_html')) {
    function safe_html($string) {
        return htmlspecialchars($string ?? '', ENT_QUOTES, 'UTF-8');
    }
}

// Prevent direct access
if (!defined('DB_HOST')) {
    die('Configuration not loaded. Include config.php first.');
}

// ============================================
// Authentication Functions
// ============================================

function isAuthenticated() {
    return isset($_SESSION['authenticated']) && $_SESSION['authenticated'] === true;
}

function requireAuth() {
    if (!isAuthenticated()) {
        header('Location: login.php');
        exit;
    }
}

function getCurrentUser() {
    if (!isAuthenticated()) {
        return null;
    }

    return [
        'id' => $_SESSION['user_id'] ?? null,
        'username' => $_SESSION['username'] ?? null,
        'email' => $_SESSION['user_email'] ?? null,
        'emails' => $_SESSION['user_emails'] ?? [],
        'role' => $_SESSION['user_role'] ?? 'viewer',
        'domains' => $_SESSION['user_domains'] ?? []
    ];
}

function checkPermission($required_role) {
    if (!isAuthenticated()) {
        return false;
    }

    $user_role = $_SESSION['user_role'] ?? 'viewer';

    $roles_hierarchy = [
        'viewer' => 1,
        'quarantine_user' => 2,
        'domain_admin' => 3,
        'admin' => 4
    ];

    $required_level = $roles_hierarchy[$required_role] ?? 0;
    $user_level = $roles_hierarchy[$user_role] ?? 0;

    return $user_level >= $required_level;
}

// ============================================
// Domain Access Functions
// ============================================

function parseEmailList(string $input, array &$invalid = []): array {
    $invalid = [];
    $emails = [];
    $seen = [];
    $parts = preg_split('/[\s,;]+/', $input);

    foreach ($parts as $part) {
        $email = trim($part);
        if ($email === '') {
            continue;
        }

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $invalid[] = $email;
            continue;
        }

        $key = strtolower($email);
        if (!isset($seen[$key])) {
            $seen[$key] = true;
            $emails[] = $email;
        }
    }

    return $emails;
}

function getQuarantineUserEmails(): array {
    $emails = $_SESSION['user_emails'] ?? [];
    if (!is_array($emails) || empty($emails)) {
        $fallback = $_SESSION['user_email'] ?? '';
        $invalid = [];
        $emails = parseEmailList((string) $fallback, $invalid);
    }

    return $emails;
}

function checkDomainAccess($email) {
    $user_role = $_SESSION['user_role'] ?? 'viewer';

    // Admin has access to everything
    if ($user_role === 'admin') {
        return true;
    }

    // Domain admin - check if email belongs to their domains
    if ($user_role === 'domain_admin') {
        $user_domains = $_SESSION['user_domains'] ?? [];

        if (empty($user_domains)) {
            return false;
        }

        // Extract domain from email
        $email_domain = '';
        if (preg_match('/@([a-zA-Z0-9.-]+)/', $email, $matches)) {
            $email_domain = strtolower($matches[1]);
        }

        // Check if email domain matches any user domain
        foreach ($user_domains as $domain) {
            if (strcasecmp($email_domain, $domain) === 0) {
                return true;
            }
        }

        return false;
    }

    if ($user_role === 'quarantine_user') {
        $user_emails = getQuarantineUserEmails();
        if (empty($user_emails)) {
            return false;
        }

        foreach ($user_emails as $user_email) {
            if (stripos((string) $email, $user_email) !== false) {
                return true;
            }
        }

        return false;
    }

    // Viewer has no access
    return false;
}

function hasDomainAccess(string $domain): bool {
    $user_role = $_SESSION['user_role'] ?? 'viewer';

    if ($user_role === 'admin') {
        return true;
    }

    if ($user_role === 'domain_admin') {
        $user_domains = $_SESSION['user_domains'] ?? [];
        foreach ($user_domains as $userDomain) {
            if (strcasecmp($domain, $userDomain) === 0) {
                return true;
            }
        }
    }

    return false;
}

function generateMd5CryptPassword(string $password): string {
    $salt = substr(bin2hex(random_bytes(6)), 0, 8);
    return crypt($password, '$1$' . $salt . '$');
}

if (!function_exists('extractEmailAddress')) {
    function extractEmailAddress($value) {
        $value = trim($value);

        if ($value === '') {
            return null;
        }

        if (filter_var($value, FILTER_VALIDATE_EMAIL)) {
            return $value;
        }

        if (preg_match('/<([^>]+)>/', $value, $matches)) {
            $candidate = trim($matches[1]);
            if (filter_var($candidate, FILTER_VALIDATE_EMAIL)) {
                return $candidate;
            }
        }

        if (preg_match('/([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/', $value, $matches)) {
            $candidate = trim($matches[1]);
            if (filter_var($candidate, FILTER_VALIDATE_EMAIL)) {
                return $candidate;
            }
        }

        return null;
    }
}

if (!function_exists('isLikelyRandomEmail')) {
    function isLikelyRandomEmail(string $email): bool {
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return false;
        }

        $parts = explode('@', $email, 2);
        $local = strtolower($parts[0] ?? '');
        if ($local === '') {
            return false;
        }

        $randomPatterns = [
            '/^(prvs|msprvs\\d*)=.+$/',
            '/^bounce-[0-9a-f]{12,}$/',
            '/^[a-f0-9]{16}-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}-[0-9]{4,}$/',
        ];

        foreach ($randomPatterns as $pattern) {
            if (preg_match($pattern, $local)) {
                return true;
            }
        }

        $normalized = preg_replace('/[^a-z0-9]/', '', $local);

        if ($normalized === null || strlen($normalized) < 12) {
            return false;
        }

        if (preg_match('/^[a-f0-9]+$/', $normalized)) {
            return true;
        }

        $digitCount = preg_match_all('/[0-9]/', $normalized);
        $alphaCount = preg_match_all('/[a-z]/', $normalized);
        $total = $digitCount + $alphaCount;

        if ($total === 0) {
            return false;
        }

        $digitRatio = $digitCount / $total;
        return $digitRatio >= 0.6;
    }
}

/**
 * Generate SQL WHERE clause for domain filtering
 * OPRAVENO: Správná syntaxe LIKE '%@domain' pro hledání domény v emailech
 * 
 * @param array &$params Reference to parameters array for prepared statement
 * @return string SQL WHERE clause
 */
function getDomainFilterSQL(&$params) {
    $user_role = $_SESSION['user_role'] ?? 'viewer';

    // Admin sees everything
    if ($user_role === 'admin') {
        return '1=1';
    }

    // Domain admin sees only their domains
    if ($user_role === 'domain_admin') {
        $user_domains = $_SESSION['user_domains'] ?? [];

        if (empty($user_domains)) {
            return '1=0'; // No domains = no access
        }

        $conditions = [];
        foreach ($user_domains as $domain) {
            // OPRAVENO: Správná syntaxe s '%@domain' místo '.@domain'
            $conditions[] = "sender LIKE ?";
            $params[] = '%@' . $domain;

            $conditions[] = "recipients LIKE ?";
            $params[] = '%@' . $domain;
        }

        return '(' . implode(' OR ', $conditions) . ')';
    }

    if ($user_role === 'quarantine_user') {
        $user_emails = getQuarantineUserEmails();
        if (empty($user_emails)) {
            return '1=0';
        }

        $conditions = [];
        foreach ($user_emails as $user_email) {
            $conditions[] = "recipients LIKE ?";
            $params[] = '%' . $user_email . '%';
            $conditions[] = "headers_to LIKE ?";
            $params[] = '%' . $user_email . '%';
        }

        return '(' . implode(' OR ', $conditions) . ')';
    }

    // Viewer sees nothing by default
    return '1=0';
}

/**
 * Check if current user can access a quarantine message row
 *
 * @param array $message Quarantine message row
 * @return bool
 */
function canAccessQuarantineMessage(array $message): bool {
    $user_role = $_SESSION['user_role'] ?? 'viewer';

    if ($user_role === 'admin') {
        return true;
    }

    if ($user_role === 'domain_admin') {
        return checkDomainAccess($message['sender'] ?? '')
            || checkDomainAccess($message['recipients'] ?? '');
    }

    if ($user_role === 'quarantine_user') {
        $user_emails = getQuarantineUserEmails();
        if (empty($user_emails)) {
            return false;
        }

        $recipients = $message['recipients'] ?? '';
        $headersTo = $message['headers_to'] ?? '';

        foreach ($user_emails as $user_email) {
            if (stripos($recipients, $user_email) !== false
                || stripos($headersTo, $user_email) !== false) {
                return true;
            }
        }

        return false;
    }

    return false;
}

// ============================================
// Audit Logging
// ============================================

function logAudit($user_id, $username, $action, $entity_type, $entity_id, $details) {
    try {
        $db = Database::getInstance()->getConnection();
        $ip_address = $_SERVER['REMOTE_ADDR'] ?? 'unknown';

        $stmt = $db->prepare("
            INSERT INTO audit_log (user_id, username, action, entity_type, entity_id, details, ip_address)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ");

        $stmt->execute([
            $user_id,
            $username,
            $action,
            $entity_type,
            $entity_id,
            $details,
            $ip_address
        ]);
    } catch (Exception $e) {
        error_log('Audit log failed: ' . $e->getMessage());
    }
}

// ============================================
// MIME Header Decoding
// ============================================

function decodeMimeHeader($header) {
    if (empty($header)) {
        return '';
    }

    $original = $header;
    // Remove quotes
    $header = trim($header, '"\'');

    $decoded = mb_decode_mimeheader($header);

    $hasEncodedWords = preg_match('/=\?[^?]+\?[BQ]\?[^?]+\?=/i', $header);
    $needsRecode = $hasEncodedWords || !mb_check_encoding($decoded, 'UTF-8');

    if ($needsRecode) {
        $iconvDecoded = iconv_mime_decode(
            $header,
            ICONV_MIME_DECODE_CONTINUE_ON_ERROR,
            'UTF-8'
        );
        if (!empty($iconvDecoded)) {
            $decoded = $iconvDecoded;
        }
    }

    if (!mb_check_encoding($decoded, 'UTF-8')) {
        $converted = mb_convert_encoding($decoded, 'UTF-8', 'UTF-8, ISO-8859-1, Windows-1250, Windows-1252');
        if (!empty($converted)) {
            $decoded = $converted;
        }
    }

    return $decoded ?: $original;
}

// ============================================
// Message Display Functions
// ============================================

function formatMessageSize($bytes) {
    $units = ['B', 'KB', 'MB', 'GB'];
    $bytes = max($bytes, 0);
    $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
    $pow = min($pow, count($units) - 1);
    $bytes /= pow(1024, $pow);

    return round($bytes, 2) . ' ' . $units[$pow];
}

function getScoreBadgeClass(float $score, string $action = ''): string {
    $action = strtolower(trim($action));
    $actionMap = [
        'no action' => 'score-action-no-action',
        'greylist' => 'score-action-greylist',
        'add header' => 'score-action-add-header',
        'rewrite subject' => 'score-action-rewrite-subject',
        'reject' => 'score-action-reject',
    ];

    if ($action !== '' && isset($actionMap[$action])) {
        return $actionMap[$action];
    }

    if ($score >= 15) {
        return 'score-high';
    }
    if ($score >= 6) {
        return 'score-medium';
    }
    return 'score-low';
}

function getMessageStateClass(int $state): string {
    switch ($state) {
        case 0:
            return 'state-quarantined';
        case 1:
            return 'state-learned-ham';
        case 2:
            return 'state-learned-spam';
        case 3:
            return 'state-released';
        default:
            return '';
    }
}

function getSymbolBadgeColor(float $score): string {
    if ($score >= 1) {
        return '#e74c3c';
    }
    if ($score > 0) {
        return '#f39c12';
    }
    if ($score < 0) {
        return '#27ae60';
    }
    return '#95a5a6';
}

// ============================================
// Mailbox Storage Functions
// ============================================

function getDirectorySize(string $path): int {
    $size = 0;
    if (!is_dir($path) || !is_readable($path)) {
        return $size;
    }

    try {
        $iterator = new DirectoryIterator($path);
    } catch (UnexpectedValueException $exception) {
        return $size;
    }

    foreach ($iterator as $file) {
        if ($file->isDot()) {
            continue;
        }

        $filePath = $file->getPathname();
        if ($file->isLink()) {
            continue;
        }

        if ($file->isFile()) {
            $size += $file->getSize();
            continue;
        }

        if ($file->isDir() && is_readable($filePath)) {
            $size += getDirectorySize($filePath);
        }
    }

    return $size;
}

function resolveMaildirPath(string $maildir, string $baseDir): ?string {
    $maildir = trim($maildir);
    if ($maildir === '') {
        return null;
    }

    if (str_starts_with($maildir, '/')) {
        return $maildir;
    }

    return rtrim($baseDir, '/') . '/' . ltrim($maildir, '/');
}

function getMaildirSize(string $maildir, string $baseDir): int {
    $path = resolveMaildirPath($maildir, $baseDir);
    if (!$path) {
        return 0;
    }

    return getDirectorySize($path);
}

function getMailboxStorageStats(string $baseDir, array &$errors = []): array {
    $stats = [];

    if (!is_dir($baseDir) || !is_readable($baseDir)) {
        $errors[] = ['type' => 'base', 'path' => $baseDir];
        return $stats;
    }

    foreach (new DirectoryIterator($baseDir) as $domainInfo) {
        if ($domainInfo->isDot() || !$domainInfo->isDir()) {
            continue;
        }

        $domainName = $domainInfo->getFilename();
        if (strpos($domainName, '.') === 0) {
            continue;
        }

        $domainPath = $domainInfo->getPathname();
        if (!is_readable($domainPath)) {
            $errors[] = ['type' => 'domain', 'domain' => $domainName];
            continue;
        }

        $mailboxes = [];
        $totalSize = 0;

        foreach (new DirectoryIterator($domainPath) as $mailboxInfo) {
            if ($mailboxInfo->isDot() || !$mailboxInfo->isDir()) {
                continue;
            }

            $mailboxName = $mailboxInfo->getFilename();
            if (strpos($mailboxName, '.') === 0) {
                continue;
            }

            $mailboxPath = $mailboxInfo->getPathname();
            if (!is_readable($mailboxPath)) {
                $errors[] = [
                    'type' => 'mailbox',
                    'domain' => $domainName,
                    'mailbox' => $mailboxName,
                ];
                continue;
            }

            $mailboxSize = getDirectorySize($mailboxPath);
            $mailboxes[] = [
                'name' => $mailboxName,
                'size' => $mailboxSize,
            ];
            $totalSize += $mailboxSize;
        }

        usort($mailboxes, function ($a, $b) {
            return strcasecmp($a['name'], $b['name']);
        });

        $stats[] = [
            'domain' => $domainName,
            'mailboxes' => $mailboxes,
            'mailbox_count' => count($mailboxes),
            'total_size' => $totalSize,
        ];
    }

    usort($stats, function ($a, $b) {
        return strcasecmp($a['domain'], $b['domain']);
    });

    return $stats;
}

/**
 * UTF-8 safe truncate
 */
function truncateText($text, $length = 50, $suffix = '...') {
    if (mb_strlen($text, 'UTF-8') <= $length) {
        return $text;
    }
    return mb_substr($text, 0, $length, 'UTF-8') . $suffix;
}

function sanitizeHtml($html) {
    // Basic sanitization
    $html = strip_tags($html, '<p><br><b><i><u><strong><em><ul><ol><li><a><img>');

    // Remove potentially dangerous attributes
    $html = preg_replace('/<a[^>]*href=["\'\']?javascript:/i', '<a', $html);
    $html = preg_replace('/\s*on\w+\s*=/i', ' ', $html);

    return $html;
}

// ============================================
// Message Helper Functions
// ============================================

/**
 * Get message by ID with domain access check
 */
function getMessageById($id, $check_domain = true) {
    $db = Database::getInstance()->getConnection();

    $stmt = $db->prepare("SELECT * FROM quarantine_messages WHERE id = ?");
    $stmt->execute([$id]);
    $message = $stmt->fetch();

    if (!$message) {
        return null;
    }

    // Check domain access for non-admins
    if ($check_domain && $_SESSION['user_role'] !== 'admin') {
        if (!checkDomainAccess($message['sender']) && !checkDomainAccess($message['recipients'])) {
            return null;
        }
    }

    return $message;
}

/**
 * Format datetime
 */
function formatDateTime($datetime, $format = 'd.m.Y H:i:s') {
    if (empty($datetime)) {
        return '';
    }

    try {
        $dt = new DateTime($datetime);
        return $dt->format($format);
    } catch (Exception $e) {
        return $datetime;
    }
}

/**
 * Format relative datetime
 */
function formatDateTimeRelative($datetime) {
    if (empty($datetime)) {
        return '';
    }

    try {
        $dt = new DateTime($datetime);
        $now = new DateTime();
        $diff = $now->diff($dt);

        if ($diff->y > 0) {
            return $diff->y . ' ' . ($diff->y == 1 ? 'rok' : 'roky') . ' nazpět';
        } elseif ($diff->m > 0) {
            return $diff->m . ' ' . ($diff->m == 1 ? 'měsíc' : 'měsíce') . ' nazpět';
        } elseif ($diff->d > 0) {
            return $diff->d . ' ' . ($diff->d == 1 ? 'den' : 'dny') . ' nazpět';
        } elseif ($diff->h > 0) {
            return $diff->h . ' ' . ($diff->h == 1 ? 'hodina' : 'hodiny') . ' nazpět';
        } elseif ($diff->i > 0) {
            return $diff->i . ' ' . ($diff->i == 1 ? 'minuta' : 'minuty') . ' nazpět';
        } else {
            return 'před chvílí';
        }
    } catch (Exception $e) {
        return $datetime;
    }
}

// ============================================
// Statistics Functions
// ============================================

/**
 * Get quarantine statistics
 */
function getQuarantineStats($days = 7) {
    $db = Database::getInstance()->getConnection();
    $params = [];
    $domain_filter = getDomainFilterSQL($params);

    $date_from = date('Y-m-d 00:00:00', strtotime("-$days days"));
    $date_to = date('Y-m-d 23:59:59');

    array_unshift($params, $date_from, $date_to);

    $sql = "
        SELECT 
            COUNT(*) as total,
            SUM(CASE WHEN state = 0 THEN 1 ELSE 0 END) as in_quarantine,
            SUM(CASE WHEN state = 1 THEN 1 ELSE 0 END) as learned_ham,
            SUM(CASE WHEN state = 2 THEN 1 ELSE 0 END) as learned_spam,
            SUM(CASE WHEN state = 3 THEN 1 ELSE 0 END) as released,
            SUM(CASE WHEN action = 'reject' THEN 1 ELSE 0 END) as rejected,
            AVG(score) as avg_score,
            MAX(score) as max_score
        FROM quarantine_messages        WHERE timestamp BETWEEN ? AND ?
        AND $domain_filter
    ";

    $stmt = $db->prepare($sql);
    $stmt->execute($params);

    return $stmt->fetch();
}

// ============================================
// CSV Export Functions
// ============================================

/**
 * Escape value for CSV export
 */
function escapeCsv($value) {
    if (strpos($value, ',') !== false || strpos($value, '"') !== false || strpos($value, "\n") !== false) {
        return '"' . str_replace('"', '""', $value) . '"';
    }
    return $value;
}

// ============================================
// Alert/Message Display
// ============================================

/**
 * Display session alerts
 */
function displayAlerts() {
    if (isset($_SESSION['success_msg'])) {
        echo '<div style="background: #d4edda; border: 1px solid #c3e6cb; color: #155724; padding: 12px 20px; border-radius: 4px; margin-bottom: 20px;">';
        echo '<i class="fas fa-check-circle"></i> ' . htmlspecialchars($_SESSION['success_msg']);
        echo '</div>';
        unset($_SESSION['success_msg']);
    }

    if (isset($_SESSION['error_msg'])) {
        echo '<div style="background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; padding: 12px 20px; border-radius: 4px; margin-bottom: 20px;">';
        echo '<i class="fas fa-exclamation-triangle"></i> ' . htmlspecialchars($_SESSION['error_msg']);
        echo '</div>';
        unset($_SESSION['error_msg']);
    }

    if (isset($_SESSION['info_msg'])) {
        echo '<div style="background: #d1ecf1; border: 1px solid #bee5eb; color: #0c5460; padding: 12px 20px; border-radius: 4px; margin-bottom: 20px;">';
        echo '<i class="fas fa-info-circle"></i> ' . htmlspecialchars($_SESSION['info_msg']);
        echo '</div>';
        unset($_SESSION['info_msg']);
    }
}

// ============================================
// Debug Functions
// ============================================

/**
 * Debug function - only for development
 */
function debug($var, $label = 'DEBUG') {
    if (defined('DEBUG_MODE') && DEBUG_MODE === true) {
        echo "<pre style='background: #f0f0f0; padding: 10px; border: 1px solid #ccc; margin: 10px 0;'>";
        echo "<strong>$label:</strong>\n";
        print_r($var);
        echo "</pre>";
    }
}

/**
 * Debug domain filtering for troubleshooting
 */
function debugDomainFilter() {
    if (!isAuthenticated()) {
        return;
    }

    $user_role = $_SESSION['user_role'] ?? 'viewer';
    $user_domains = $_SESSION['user_domains'] ?? [];

    echo "<div style='background: #fff3cd; border: 1px solid #ffc107; padding: 15px; margin: 10px 0;'>";
    echo "<h4>🔍 Domain Filter Debug</h4>";
    echo "<strong>User Role:</strong> $user_role<br>";
    echo "<strong>User Domains:</strong> " . (empty($user_domains) ? 'ŽÁDNÉ' : implode(', ', $user_domains)) . "<br>";

    $params = [];
    $filter = getDomainFilterSQL($params);
    echo "<strong>SQL Filter:</strong> <code>$filter</code><br>";
    echo "<strong>Params:</strong> <code>" . implode(', ', $params) . "</code>";
    echo "</div>";
}

// ========================================================================
// DATABASE FILTER FUNCTIONS - UNIFIED WHERE CLAUSE BUILDERS
// ========================================================================

/**
 * Vytvoří WHERE klauzuli a parametry pro quarantine_messages dotazy
 * 
 * @param array $filters Asociativní pole s filtry z $_GET
 * @param array &$params Reference na pole parametrů (bude naplněno)
 * @return string WHERE klauzule (bez "WHERE")
 */
function buildQuarantineWhereClause($filters = [], &$params = []) {
    $where = [];
    $params = [];

    // Domain filter - MUST BE FIRST!
    $domain_filter = getDomainFilterSQL($params);
    $where[] = $domain_filter;

    // Search filter
    if (!empty($filters['search'])) {
        $search = '%' . $filters['search'] . '%';
        $where[] = "(sender LIKE ? OR headers_from LIKE ? OR recipients LIKE ? OR headers_to LIKE ? OR subject LIKE ? OR message_id LIKE ?)";
        $params[] = $search;
        $params[] = $search;
        $params[] = $search;
        $params[] = $search;
        $params[] = $search;
        $params[] = $search;
    }

    // Action filter
    if (!empty($filters['action'])) {
        $where[] = "action = ?";
        $params[] = $filters['action'];
    }

    // Score min filter
    if (isset($filters['score_min']) && $filters['score_min'] !== '') {
        $where[] = "score >= ?";
        $params[] = floatval($filters['score_min']);
    }

    // Score max filter
    if (isset($filters['score_max']) && $filters['score_max'] !== '') {
        $where[] = "score <= ?";
        $params[] = floatval($filters['score_max']);
    }

    // Released filter
    // State filter (0=quarantine, 1=learned_ham, 2=learned_spam, 3=released)
    if (isset($filters['statefilter']) && $filters['statefilter'] !== '') {
        $where[] = "state = ?";
        $params[] = (int)$filters['statefilter'];
    }

    // Date from filter
    if (!empty($filters['date'])) {
        $where[] = "timestamp >= ?";
        $params[] = $filters['date'] . ' 00:00:00';
        $where[] = "timestamp <= ?";
        $params[] = $filters['date'] . ' 23:59:59';
    }

    // Sender filter
    if (!empty($filters['sender'])) {
        $where[] = "(sender LIKE ? OR headers_from LIKE ?)";
        $params[] = '%' . $filters['sender'] . '%';
        $params[] = '%' . $filters['sender'] . '%';
    }

    // Recipient filter
    if (!empty($filters['recipient'])) {
        $where[] = "(recipients LIKE ? OR headers_to LIKE ?)";
        $params[] = '%' . $filters['recipient'] . '%';
        $params[] = '%' . $filters['recipient'] . '%';
    }

    // Symbol filters
    $symbolFilters = [];
    if (!empty($filters['virus'])) {
        $symbolFilters[] = "symbols LIKE ?";
        $params[] = '%ESET_VIRUS%';
        $symbolFilters[] = "symbols LIKE ?";
        $params[] = '%CLAM_VIRUS%';
    }
    if (!empty($filters['bad_extension'])) {
        $symbolFilters[] = "symbols LIKE ?";
        $params[] = '%BAD_ATTACHMENT_EXT%';
    }
    if (!empty($symbolFilters)) {
        $where[] = '(' . implode(' OR ', $symbolFilters) . ')';
    }

    return implode(' AND ', $where);
}


/**
 * Vytvoří kompletní SELECT dotaz pro quarantine_messages s filtry
 * 
 * @param array $filters Filtry z $_GET
 * @param array &$params Reference na parametry (bude naplněno)
 * @param array $options Dodatečné parametry dotazu
 * @return string Kompletní SQL dotaz
 */
function buildQuarantineQuery($filters = [], &$params = [], $options = []) {
    $defaults = [
        'select' => 'id, message_id, timestamp, sender, recipients, subject, action, score, hostname, state, state_at, state_by, IFNULL(LENGTH(message_content), 0) as size_bytes',
        'order_by' => 'timestamp DESC',
        'limit' => null,
        'offset' => 0
    ];
    $options = array_merge($defaults, $options);

    $where_clause = buildQuarantineWhereClause($filters, $params);

    // If where_clause is empty, use 1=1 as fallback to prevent SQL syntax errors
    if (empty(trim($where_clause))) {
        $where_clause = '1=1';
    }

    $sql = "SELECT {$options['select']} FROM quarantine_messages WHERE $where_clause";

    if ($options['order_by']) {
        $sql .= " ORDER BY {$options['order_by']}";
    }

    if ($options['limit']) {
        $sql .= " LIMIT " . intval($options['limit']);
        if ($options['offset']) {
            $sql .= " OFFSET " . intval($options['offset']);
        }
    }

    return $sql;
}


/**
 * Spočítá celkový počet záznamů pro quarantine dotaz
 * 
 * @param PDO $db Database connection
 * @param array $filters Filtry
 * @return int Počet záznamů
 */
function countQuarantineMessages($db, $filters = []) {
    $params = [];
    $where_clause = buildQuarantineWhereClause($filters, $params);

    $sql = "SELECT COUNT(*) FROM quarantine_messages WHERE $where_clause";
    $stmt = $db->prepare($sql);
    $stmt->execute($params);

    return (int) $stmt->fetchColumn();
}

/**
 * Spočítá celkový počet záznamů pro trace dotaz
 * 
 * @param PDO $db Database connection
 * @param array $filters Filtry
 * @return int Počet záznamů
 */
function countTraceRecords($db, $filters = []) {
    $params = [];
    $where_clause = buildTraceWhereClause($filters, $params);

    $sql = "SELECT COUNT(*) FROM trace_log WHERE $where_clause";
    $stmt = $db->prepare($sql);
    $stmt->execute($params);

    return (int) $stmt->fetchColumn();
}

/**
 * Získá rozšířené statistiky pro quarantine zprávy podle filtrů
 * ROZŠÍŘENÁ VERZE - zahrnuje i rozdělení podle akcí
 * 
 * @param PDO $db Database connection
 * @param array $filters Filtry
 * @return array Rozšířené statistiky
 */
function getExtendedQuarantineStats($db, $filters = []) {
    $params = [];
    $where_clause = buildQuarantineWhereClause($filters, $params);

    $sql = "
        SELECT 
            COUNT(*) as total,
            SUM(CASE WHEN action = 'reject' THEN 1 ELSE 0 END) as rejected,
            SUM(CASE WHEN action = 'no action' THEN 1 ELSE 0 END) as passed,
            SUM(CASE WHEN action = 'add header' THEN 1 ELSE 0 END) as marked,
            SUM(CASE WHEN state = 0 THEN 1 ELSE 0 END) as quarantined,
            SUM(CASE WHEN state = 1 THEN 1 ELSE 0 END) as learned_ham,
            SUM(CASE WHEN state = 2 THEN 1 ELSE 0 END) as learned_spam,
            SUM(CASE WHEN state = 3 THEN 1 ELSE 0 END) as released,
            AVG(score) as avg_score,
            MAX(score) as max_score,
            MIN(score) as min_score
        FROM quarantine_messages
        WHERE $where_clause    ";

    $stmt = $db->prepare($sql);
    $stmt->execute($params);

    $result = $stmt->fetch(PDO::FETCH_ASSOC);

    return [
        'total' => (int)$result['total'],
        'rejected' => (int)$result['rejected'],
        'passed' => (int)$result['passed'],
        'marked' => (int)$result['marked'],
        'quarantined' => (int)$result['quarantined'],
        'learned_ham' => (int)$result['learned_ham'],
        'learned_spam' => (int)$result['learned_spam'],
        'released' => (int)$result['released'],
        'avg_score' => (float)$result['avg_score'],
        'max_score' => (float)$result['max_score'],
        'min_score' => (float)$result['min_score'],
    ];
}


// ========================================================================
// STATISTICS DISPLAY FUNCTIONS
// ========================================================================

/**
 * Vygeneruje HTML pro zobrazení statistik
 * 
 * @param array $stats Pole se statistickými daty
 * @param array $config Konfigurace zobrazení
 * @return string HTML kód statistik
 */
function renderStats($stats, $config = []) {
    $defaults = [
        'show_total' => true,
        'show_rejected' => true,
        'show_passed' => true,
        'show_marked' => true,
        'show_score' => true,
        'show_quarantined' => false,
        'show_learned_ham' => false,
        'show_learned_spam' => false,
        'show_released' => false,
        'show_percentages' => true,
        'columns' => null,
        'size' => 'normal',
        'cssclass' => 'stats-row stats-grid-fixed',
    ];

    $config = array_merge($defaults, $config);

    $stats = array_merge([
        'total' => 0,
        'rejected' => 0,
        'passed' => 0,
        'marked' => 0,
        'avg_score' => 0,
        'min_score' => 0,
        'max_score' => 0,
        'learned_ham' => 0,
        'learned_spam' => 0,
        'quarantined' => 0,
        'released' => 0
    ], $stats);

    $visible_boxes = 0;
    if ($config['show_total']) $visible_boxes++;
    if ($config['show_rejected']) $visible_boxes++;
    if ($config['show_passed']) $visible_boxes++;
    if ($config['show_marked']) $visible_boxes++;
    if ($config['show_score']) $visible_boxes++;
    if ($config['show_quarantined']) $visible_boxes++;
    if ($config['show_learned_ham']) $visible_boxes++;
    if ($config['show_learned_spam']) $visible_boxes++;
    if ($config['show_released']) $visible_boxes++;
    if ($config['show_state']) $visible_boxes++;

    if ($config['columns'] === null) {
        if ($visible_boxes <= 3) $config['columns'] = $visible_boxes;
        elseif ($visible_boxes == 4) $config['columns'] = 4;
        else $config['columns'] = 5;
    }

    ob_start();
    ?>

    <div class="<?php echo htmlspecialchars($config['cssclass']); ?> stats-size-<?php echo htmlspecialchars($config['size']); ?>" 
         style="grid-template-columns: repeat(<?php echo $config['columns']; ?>, 1fr);">

        <?php if ($config['show_total']): ?>
            <div class="stat-box">
                <div class="stat-label">
                    <i class="fas fa-envelope"></i> Celkem zpráv
                </div>
                <div class="stat-value">
                    <?php echo number_format($stats['total']); ?>
                </div>
            </div>
        <?php endif; ?>

        <?php if ($config['show_rejected']): ?>
            <div class="stat-box danger">
                <div class="stat-label">
                    <i class="fas fa-ban"></i> Odmítnuto
                </div>
                <div class="stat-value">
                    <?php echo number_format($stats['rejected']); ?>
                </div>
                <?php if ($config['show_percentages'] && $stats['total'] > 0): ?>
                    <div class="stat-change">
                        <?php echo number_format(($stats['rejected'] / $stats['total']) * 100, 1); ?>% z celku
                    </div>
                <?php endif; ?>
            </div>
        <?php endif; ?>

        <?php if ($config['show_passed']): ?>
            <div class="stat-box success">
                <div class="stat-label">
                    <i class="fas fa-check-circle"></i> Prošlo
                </div>
                <div class="stat-value">
                    <?php echo number_format($stats['passed']); ?>
                </div>
                <?php if ($config['show_percentages'] && $stats['total'] > 0): ?>
                    <div class="stat-change">
                        <?php echo number_format(($stats['passed'] / $stats['total']) * 100, 1); ?>% z celku
                    </div>
                <?php endif; ?>
            </div>
        <?php endif; ?>

        <?php if ($config['show_marked']): ?>
            <div class="stat-box warning">
                <div class="stat-label">
                    <i class="fas fa-exclamation-triangle"></i> Add Header
                </div>
                <div class="stat-value">
                    <?php echo number_format($stats['marked']); ?>
                </div>
                <?php if ($config['show_percentages'] && $stats['total'] > 0): ?>
                    <div class="stat-change">
                        <?php echo number_format(($stats['marked'] / $stats['total']) * 100, 1); ?>% z celku
                    </div>
                <?php endif; ?>
            </div>
        <?php endif; ?>

        <?php if ($config['show_quarantined'] && isset($stats['quarantined'])): ?>
            <div class="stat-box warning">
                <div class="stat-label">
                    <i class="fas fa-pause-circle"></i> V karanténě
                </div>
                <div class="stat-value">
                    <?php echo number_format($stats['quarantined']); ?>
                </div>
                <?php if ($config['show_percentages'] && $stats['total'] > 0): ?>
                    <div class="stat-change">
                        <?php echo number_format(($stats['quarantined'] / $stats['total']) * 100, 1); ?>% z celku
                    </div>
                <?php endif; ?>
            </div>
        <?php endif; ?>

        <?php if ($config['show_released'] && isset($stats['released'])): ?>
            <div class="stat-box success">
                <div class="stat-label">
                    <i class="fas fa-unlock"></i> Uvolněno
                </div>
                <div class="stat-value">
                    <?php echo number_format($stats['released']); ?>
                </div>
                <?php if ($config['show_percentages'] && $stats['total'] > 0): ?>
                    <div class="stat-change">
                        <?php echo number_format(($stats['released'] / $stats['total']) * 100, 1); ?>% z celku
                    </div>
                <?php endif; ?>
            </div>
        <?php endif; ?>

        <?php if ($config['show_learned_ham'] && isset($stats['learned_ham'])): ?>
            <div class="stat-box success">
                <div class="stat-label">
                    <i class="fas fa-unlock"></i> Uvolněno
                </div>
                <div class="stat-value">
                    <?php echo number_format($stats['learned_ham']); ?>
                </div>
                <?php if ($config['show_percentages'] && $stats['total'] > 0): ?>
                    <div class="stat-change">
                        <?php echo number_format(($stats['learned_ham'] / $stats['total']) * 100, 1); ?>% z celku
                    </div>
                <?php endif; ?>
            </div>
        <?php endif; ?>

        <?php if ($config['show_learned_spam'] && isset($stats['learned_spam'])): ?>
            <div class="stat-box success">
                <div class="stat-label">
                    <i class="fas fa-unlock"></i> Uvolněno
                </div>
                <div class="stat-value">
                    <?php echo number_format($stats['learned_spam']); ?>
                </div>
                <?php if ($config['show_percentages'] && $stats['total'] > 0): ?>
                    <div class="stat-change">
                        <?php echo number_format(($stats['learned_spam'] / $stats['total']) * 100, 1); ?>% z celku
                    </div>
                <?php endif; ?>
            </div>
        <?php endif; ?>

        <?php if ($config['show_score']): ?>
            <div class="stat-box">
                <div class="stat-label">
                    <i class="fas fa-chart-line"></i> Průměrné skóre
                </div>
                <div class="stat-value">
                    <?php echo number_format($stats['avg_score'], 2); ?>
                </div>
                <div class="stat-change">
                    Min: <?php echo number_format($stats['min_score'], 1); ?> | 
                    Max: <?php echo number_format($stats['max_score'], 1); ?>
                </div>
            </div>
        <?php endif; ?>
    </div>

    <?php
    return ob_get_clean();
}

/**
 * Renderuje stats row (jednoduchý řádek statistik)
 * 
 * @param array $stats_boxes Pole boxů
 * @return string HTML kód
 */
function renderStatsRow($stats_boxes) {
    if (empty($stats_boxes)) {
        return '';
    }

    ob_start();
    ?>

    <div class="stats-row">
        <?php foreach ($stats_boxes as $box): ?>
            <div class="stat-box <?php echo htmlspecialchars($box['class'] ?? ''); ?>">
                <div class="stat-label">
                    <i class="<?php echo htmlspecialchars($box['icon'] ?? 'fas fa-info'); ?>"></i> 
                    <?php echo htmlspecialchars($box['label']); ?>
                </div>
                <div class="stat-value">
                    <?php echo htmlspecialchars($box['value']); ?>
                </div>
                <?php if (isset($box['change'])): ?>
                    <div class="stat-change">
                        <?php echo htmlspecialchars($box['change']); ?>
                    </div>
                <?php endif; ?>
            </div>
        <?php endforeach; ?>
    </div>

    <?php
    return ob_get_clean();
}

/**
 * Vytvoří stats boxes z dat pro použití s renderStatsRow()
 * 
 * @param array $stats Statistická data
 * @param array $config Konfigurace které boxy zobrazit
 * @return array Stats boxes
 */
function buildStatsBoxes($stats, $config = []) {
    $defaults = [
        'show_total' => true,
        'show_quarantined' => true,
        'show_state' => true,
        'show_avg_score' => true,
        'show_max_score' => true
    ];

    $config = array_merge($defaults, $config);
    $boxes = [];

    if ($config['show_total']) {
        $boxes[] = [
            'label' => 'Celkem nalezeno',
            'value' => number_format($stats['total']),
            'icon' => 'fas fa-envelope',
            'class' => ''
        ];
    }

    if ($config['show_quarantined'] && isset($stats['quarantined'])) {
        $boxes[] = [
            'label' => 'V karanténě',
            'value' => number_format($stats['quarantined']),
            'icon' => 'fas fa-pause-circle',
            'class' => 'warning'
        ];
    }

    if ($config['show_state'] && isset($stats['released'])) {
        $boxes[] = [
            'label' => 'Uvolněno',
            'value' => number_format($stats['released']),
            'icon' => 'fas fa-check-circle',
            'class' => 'success'
        ];
    }

    if ($config['show_avg_score']) {
        $boxes[] = [
            'label' => 'Avg skóre',
            'value' => number_format($stats['avg_score'], 1),
            'icon' => 'fas fa-chart-line',
            'class' => ''
        ];
    }

    if ($config['show_max_score']) {
        $boxes[] = [
            'label' => 'Max skóre',
            'value' => number_format($stats['max_score'], 1),
            'icon' => 'fas fa-arrow-up',
            'class' => 'danger'
        ];
    }

    return $boxes;
}

// End of unified filter and stats functions



/**
 * Renderuje statistiky v inline/kompaktním formátu (na jednom řádku)
 * 
 * @param array $stats Pole se statistickými daty
 * @param array $config Konfigurace zobrazení
 * @return string HTML kód statistik
 */
function renderStatsInline($stats, $config = []) {
    $defaults = [
        'show_total' => true,
        'show_rejected' => true,
        'show_marked' => true,
        'show_passed' => false,
        'show_quarantined' => false,
        'show_learned_ham' => false,
        'show_learned_spam' => false,
        'show_released' => false,
        'show_avg_score' => true,
        'show_max_score' => false,
        'show_min_score' => false,
    ];

    $config = array_merge($defaults, $config);

    $stats = array_merge([
        'total' => 0,
        'rejected' => 0,
        'passed' => 0,
        'marked' => 0,
        'quarantined' => 0,
        'learned_ham' => 0,
        'learned_spam' => 0,
        'released' => 0,
        'avg_score' => 0,
        'max_score' => 0,
        'min_score' => 0,
    ], $stats);

    ob_start();
    ?>

    <div class="stats-inline">
        <?php if ($config['show_total'] && isset($stats['total'])): ?>
        <div class="stat-inline-item total">
            <span class="stat-inline-label">Celkem:</span>
            <span class="stat-inline-value"><?php echo number_format($stats['total']); ?></span>
        </div>
        <?php endif; ?>

        <?php if ($config['show_rejected'] && isset($stats['rejected'])): ?>
        <div class="stat-inline-item reject">
            <span class="stat-inline-label">Reject:</span>
            <span class="stat-inline-value"><?php echo number_format($stats['rejected']); ?></span>
        </div>
        <?php endif; ?>

        <?php if ($config['show_passed'] && isset($stats['passed'])): ?>
        <div class="stat-inline-item passed">
            <span class="stat-inline-label">Passed:</span>
            <span class="stat-inline-value"><?php echo number_format($stats['passed']); ?></span>
        </div>
        <?php endif; ?>

        <?php if ($config['show_marked'] && isset($stats['marked'])): ?>
        <div class="stat-inline-item marked">
            <span class="stat-inline-label">Header:</span>
            <span class="stat-inline-value"><?php echo number_format($stats['marked']); ?></span>
        </div>
        <?php endif; ?>

        <?php if ($config['show_quarantined'] && isset($stats['quarantined'])): ?>
        <div class="stat-inline-item quarantined">
            <span class="stat-inline-label">Karanténa:</span>
            <span class="stat-inline-value"><?php echo number_format($stats['quarantined']); ?></span>
        </div>
        <?php endif; ?>

        <?php if ($config['show_learned_ham'] && isset($stats['learned_ham'])): ?>
        <div class="stat-inline-item learned-ham">
            <span class="stat-inline-label">👍 HAM:</span>
            <span class="stat-inline-value"><?php echo number_format($stats['learned_ham']); ?></span>
        </div>
        <?php endif; ?>

        <?php if ($config['show_learned_spam'] && isset($stats['learned_spam'])): ?>
        <div class="stat-inline-item learned-spam">
            <span class="stat-inline-label">👎 SPAM:</span>
            <span class="stat-inline-value"><?php echo number_format($stats['learned_spam']); ?></span>
        </div>
        <?php endif; ?>

        <?php if ($config['show_released'] && isset($stats['released'])): ?>
        <div class="stat-inline-item released">
            <span class="stat-inline-label">✓ Uvolněno:</span>
            <span class="stat-inline-value"><?php echo number_format($stats['released']); ?></span>
        </div>
        <?php endif; ?>

        <?php if ($config['show_avg_score'] && isset($stats['avg_score'])): ?>
        <div class="stat-inline-item score">
            <span class="stat-inline-label">Ø Skóre:</span>
            <span class="stat-inline-value"><?php echo number_format($stats['avg_score'], 1); ?></span>
        </div>
        <?php endif; ?>

        <?php if ($config['show_max_score'] && isset($stats['max_score'])): ?>
        <div class="stat-inline-item score-max">
            <span class="stat-inline-label">Max:</span>
            <span class="stat-inline-value"><?php echo number_format($stats['max_score'], 1); ?></span>
        </div>
        <?php endif; ?>

        <?php if ($config['show_min_score'] && isset($stats['min_score'])): ?>
        <div class="stat-inline-item score-min">
            <span class="stat-inline-label">Min:</span>
            <span class="stat-inline-value"><?php echo number_format($stats['min_score'], 1); ?></span>
        </div>
        <?php endif; ?>
    </div>

    <?php
    return ob_get_clean();
}


// ============================================
// TRACE MESSAGE FUNCTIONS
// ============================================

/**
 * Count trace messages with filters
 */
function countTraceMessages($db, $filters = []) {
    $params = [];
    $where = ['1=1'];

    // Domain filter
    $domain_filter = getDomainFilterSQL($params);
    $where[] = $domain_filter;

    // Apply filters
    applyTraceFilters($filters, $where, $params);

    $sql = "SELECT COUNT(*) FROM message_trace WHERE " . implode(' AND ', $where);
    $stmt = $db->prepare($sql);
    $stmt->execute($params);

    return (int)$stmt->fetchColumn();
}

/**
 * Build trace query with filters
 */
function buildTraceQuery($filters = [], &$params = [], $options = []) {
    $defaults = [
        'order_by' => 'timestamp DESC',
        'limit' => null,
        'offset' => 0,
    ];
    $options = array_merge($defaults, $options);

    $where = ['1=1'];

    // Domain filter
    $domain_filter = getDomainFilterSQL($params);
    $where[] = $domain_filter;

    // Apply filters
    applyTraceFilters($filters, $where, $params);

    $sql = "
        SELECT 
            id,
            message_id,
            queue_id,
            timestamp,
            sender,
            recipients,
            subject,
            ip_address,
            authenticated_user,
            action,
            score,
            symbols,
            hostname,
            size_bytes
        FROM message_trace
        WHERE " . implode(' AND ', $where) . "
    ";

    if ($options['order_by']) {
        $sql .= " ORDER BY {$options['order_by']}";
    }

    if ($options['limit']) {
        $sql .= " LIMIT " . (int)$options['limit'];
        if ($options['offset']) {
            $sql .= " OFFSET " . (int)$options['offset'];
        }
    }

    return $sql;
}

/**
 * Apply trace filters to WHERE clause
 */
function applyTraceFilters($filters, &$where, &$params) {
    // Search filter
    if (!empty($filters['search'])) {
        $search = '%' . $filters['search'] . '%';
        $where[] = "(sender LIKE ? OR recipients LIKE ? OR subject LIKE ? OR message_id LIKE ? OR ip_address LIKE ?)";
        $params[] = $search;
        $params[] = $search;
        $params[] = $search;
        $params[] = $search;
        $params[] = $search;
    }

    // Sender filter
    if (!empty($filters['sender'])) {
        $where[] = "sender LIKE ?";
        $params[] = '%' . $filters['sender'] . '%';
    }

    // Recipient filter
    if (!empty($filters['recipient'])) {
        $where[] = "recipients LIKE ?";
        $params[] = '%' . $filters['recipient'] . '%';
    }

    // Action filter
    if (!empty($filters['action'])) {
        $where[] = "action = ?";
        $params[] = $filters['action'];
    }

    // IP filter
    if (!empty($filters['ip'])) {
        $where[] = "ip_address = ?";
        $params[] = $filters['ip'];
    }

    // Authenticated user filter
    if (!empty($filters['auth_user'])) {
        $where[] = "authenticated_user = ?";
        $params[] = $filters['auth_user'];
    }

    // Hostname filter
    if (!empty($filters['hostname'])) {
        $where[] = "hostname LIKE ?";
        $params[] = '%' . $filters['hostname'] . '%';
    }

    // Score filters
    if (isset($filters['score_min']) && $filters['score_min'] !== '') {
        $where[] = "score >= ?";
        $params[] = floatval($filters['score_min']);
    }

    if (isset($filters['score_max']) && $filters['score_max'] !== '') {
        $where[] = "score <= ?";
        $params[] = floatval($filters['score_max']);
    }

    // Date filters
    if (!empty($filters['date_from'])) {
        $where[] = "timestamp >= ?";
        $params[] = $filters['date_from'] . ' 00:00:00';
    }

    if (!empty($filters['date_to'])) {
        $where[] = "timestamp <= ?";
        $params[] = $filters['date_to'] . ' 23:59:59';
    }
}

/**
 * Get trace statistics
 */
function getTraceStats($db, $filters = []) {
    $params = [];
    $where = ['1=1'];

    // Domain filter
    $domain_filter = getDomainFilterSQL($params);
    $where[] = $domain_filter;

    // Apply filters
    applyTraceFilters($filters, $where, $params);

    $sql = "
        SELECT 
            COUNT(*) as total,
            SUM(CASE WHEN action = 'reject' THEN 1 ELSE 0 END) as rejected,
            SUM(CASE WHEN action = 'no action' THEN 1 ELSE 0 END) as passed,
            SUM(CASE WHEN action = 'add header' THEN 1 ELSE 0 END) as marked,
            SUM(CASE WHEN action = 'greylist' THEN 1 ELSE 0 END) as greylisted,
            SUM(CASE WHEN action = 'soft reject' THEN 1 ELSE 0 END) as soft_rejected,
            AVG(score) as avg_score,
            MAX(score) as max_score,
            MIN(score) as min_score
        FROM message_trace
        WHERE " . implode(' AND ', $where);

    $stmt = $db->prepare($sql);
    $stmt->execute($params);
    $stats = $stmt->fetch(PDO::FETCH_ASSOC);

    return [
        'total' => (int)($stats['total'] ?? 0),
        'rejected' => (int)($stats['rejected'] ?? 0),
        'passed' => (int)($stats['passed'] ?? 0),
        'marked' => (int)($stats['marked'] ?? 0),
        'greylisted' => (int)($stats['greylisted'] ?? 0),
        'soft_rejected' => (int)($stats['soft_rejected'] ?? 0),
        'avg_score' => round($stats['avg_score'] ?? 0, 2),
        'max_score' => round($stats['max_score'] ?? 0, 2),
        'min_score' => round($stats['min_score'] ?? 0, 2),
    ];
}

/**
 * Get trace statistics by action (for chart/reporting)
 */
function getTraceStatsByAction($db, $filters = []) {
    $params = [];
    $where = ['1=1'];

    // Domain filter
    $domain_filter = getDomainFilterSQL($params);
    $where[] = $domain_filter;

    // Apply filters (without action filter)
    $filters_no_action = $filters;
    unset($filters_no_action['action']);
    applyTraceFilters($filters_no_action, $where, $params);

    $sql = "
        SELECT 
            action,
            COUNT(*) as count,
            AVG(score) as avg_score,
            MAX(score) as max_score
        FROM message_trace
        WHERE " . implode(' AND ', $where) . "
        GROUP BY action
        ORDER BY count DESC
    ";

    $stmt = $db->prepare($sql);
    $stmt->execute($params);

    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

/**
 * Get trace statistics by time period
 */
function getTraceStatsByTime($db, $filters = [], $period = 'hour') {
    $params = [];
    $where = ['1=1'];

    // Domain filter
    $domain_filter = getDomainFilterSQL($params);
    $where[] = $domain_filter;

    // Apply filters
    applyTraceFilters($filters, $where, $params);

    // Date format based on period
    $dateFormat = match($period) {
        'hour' => '%Y-%m-%d %H:00:00',
        'day' => '%Y-%m-%d',
        'month' => '%Y-%m',
        default => '%Y-%m-%d'
    };

    $sql = "
        SELECT 
            DATE_FORMAT(timestamp, ?) as period,
            COUNT(*) as total,
            SUM(CASE WHEN action = 'reject' THEN 1 ELSE 0 END) as rejected,
            SUM(CASE WHEN action = 'no action' THEN 1 ELSE 0 END) as passed,
            AVG(score) as avg_score
        FROM message_trace
        WHERE " . implode(' AND ', $where) . "
        GROUP BY period
        ORDER BY period DESC
        LIMIT 24
    ";

    array_unshift($params, $dateFormat);

    $stmt = $db->prepare($sql);
    $stmt->execute($params);

    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

/**
 * Get top senders from trace
 */
function getTopSenders($db, $filters = [], $limit = 10) {
    $params = [];
    $where = ['1=1'];

    // Domain filter
    $domain_filter = getDomainFilterSQL($params);
    $where[] = $domain_filter;

    // Apply filters
    applyTraceFilters($filters, $where, $params);

    $sql = "
        SELECT 
            sender,
            COUNT(*) as count,
            SUM(CASE WHEN action = 'reject' THEN 1 ELSE 0 END) as rejected,
            AVG(score) as avg_score,
            MAX(score) as max_score
        FROM message_trace
        WHERE " . implode(' AND ', $where) . "
        GROUP BY sender
        ORDER BY count DESC
        LIMIT ?
    ";

    $params[] = (int)$limit;

    $stmt = $db->prepare($sql);
    $stmt->execute($params);

    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

/**
 * Get top sender domains for spam or high-score messages
 */
function getTopSenderDomains($db, $dateFrom, $dateTo, $domainFilter, $params, $scoreMin, $scoreMax, $limit = 10) {
    $domainFilterTrace = str_replace(['sender', 'recipients'], ['mt.sender', 'mt.recipients'], $domainFilter);

    $scoreMin = is_numeric($scoreMin) ? (float)$scoreMin : 0.0;
    $scoreMax = is_numeric($scoreMax) ? (float)$scoreMax : $scoreMin;
    if ($scoreMax < $scoreMin) {
        $scoreMax = $scoreMin;
    }

    $sql = "SELECT 
                LOWER(SUBSTRING_INDEX(mt.sender, '@', -1)) as sender_domain,
                COUNT(*) as count,
                AVG(mt.score) as avg_score,
                MAX(mt.score) as max_score
            FROM message_trace mt
            WHERE mt.timestamp BETWEEN ? AND ?
            AND ($domainFilterTrace)
            AND mt.sender LIKE '%@%'
            AND mt.score >= ?
            AND mt.score <= ?
            GROUP BY sender_domain
            ORDER BY count DESC
            LIMIT ?";

    $stmt = $db->prepare($sql);
    $stmt->execute(array_merge([$dateFrom, $dateTo], $params, [$scoreMin, $scoreMax, (int)$limit]));

    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

/**
 * Get top recipients from trace
 */
function getTopRecipients($db, $filters = [], $limit = 10) {
    $params = [];
    $where = ['1=1'];

    // Domain filter
    $domain_filter = getDomainFilterSQL($params);
    $where[] = $domain_filter;

    // Apply filters
    applyTraceFilters($filters, $where, $params);

    $sql = "
        SELECT 
            recipients,
            COUNT(*) as count,
            SUM(CASE WHEN action = 'reject' THEN 1 ELSE 0 END) as rejected,
            AVG(score) as avg_score,
            MAX(score) as max_score
        FROM message_trace
        WHERE " . implode(' AND ', $where) . "
        GROUP BY recipients
        ORDER BY count DESC
        LIMIT ?
    ";

    $params[] = (int)$limit;

    $stmt = $db->prepare($sql);
    $stmt->execute($params);

    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

/**
 * Parse symbols string into symbol/score pairs
 */
function parseSymbolsForStats($symbols) {
    $parsedSymbols = [];

    if (empty($symbols)) {
        return $parsedSymbols;
    }

    if (preg_match_all('/"name":"([^"]+)".*?"score":([+-]?\d+(?:\.\d+)?)/s', $symbols, $matches, PREG_SET_ORDER)) {
        foreach ($matches as $match) {
            $parsedSymbols[] = [
                'name' => $match[1],
                'score' => (float)$match[2]
            ];
        }
        return $parsedSymbols;
    }

    $decoded = json_decode($symbols, true);
    if (is_array($decoded)) {
        foreach ($decoded as $key => $value) {
            if (is_array($value)) {
                $name = $value['name'] ?? (is_string($key) ? $key : null);
                if ($name !== null) {
                    $parsedSymbols[] = [
                        'name' => $name,
                        'score' => isset($value['score']) ? (float)$value['score'] : 0.0
                    ];
                }
            } elseif (is_string($key) && is_numeric($value)) {
                $parsedSymbols[] = [
                    'name' => $key,
                    'score' => (float)$value
                ];
            }
        }
        if (!empty($parsedSymbols)) {
            return $parsedSymbols;
        }
    }

    $symbolList = explode(',', $symbols);
    foreach ($symbolList as $symbol) {
        $symbol = trim($symbol);
        if ($symbol === '') {
            continue;
        }
        if (preg_match('/^([A-Z0-9_]+)\s*\(([-+]?\d+(?:\.\d+)?)\)$/i', $symbol, $match)) {
            $parsedSymbols[] = [
                'name' => $match[1],
                'score' => (float)$match[2]
            ];
        } else {
            $parsedSymbols[] = [
                'name' => $symbol,
                'score' => 0.0
            ];
        }
    }

    return $parsedSymbols;
}

/**
 * Parse symbols string into entries with options for antivirus stats.
 */
function parseSymbolsWithOptions($symbols) {
    $entries = [];

    if (empty($symbols)) {
        return $entries;
    }
    $decoded = json_decode($symbols, true);
    if (is_array($decoded)) {
        foreach ($decoded as $key => $value) {
            if (!is_array($value)) {
                continue;
            }
            $name = $value['name'] ?? (is_string($key) ? $key : null);
            if ($name === null || $name === '') {
                continue;
            }
            $options = [];
            if (array_key_exists('options', $value)) {
                if (is_array($value['options'])) {
                    foreach ($value['options'] as $option) {
                        if (is_string($option) && $option !== '') {
                            $options[] = $option;
                        }
                    }
                } elseif (is_string($value['options']) && $value['options'] !== '') {
                    $options[] = $value['options'];
                }
            }
            $entries[] = [
                'name' => $name,
                'score' => isset($value['score']) ? (float)$value['score'] : 0.0,
                'options' => $options
            ];
        }
        if (!empty($entries)) {
            return $entries;
        }
    }

    if (preg_match_all('/"name":"([^"]+)".*?"options":\s*\[([^\]]*)\]/s', $symbols, $matches, PREG_SET_ORDER)) {
        foreach ($matches as $match) {
            $options = json_decode('[' . $match[2] . ']', true);
            if (!is_array($options)) {
                $options = [];
                if (preg_match_all('/"([^"]+)"/', $match[2], $optionMatches)) {
                    foreach ($optionMatches[1] as $option) {
                        if ($option !== '') {
                            $options[] = $option;
                        }
                    }
                }
            }
            $entries[] = [
                'name' => $match[1],
                'score' => 0.0,
                'options' => $options
            ];
        }
    }

    return $entries;
}

/**
 * Build parsed symbol data and status symbol matches for message lists.
 */
function buildMessageSymbolData($symbols) {
    $parsedSymbols = parseSymbolsForStats($symbols);
    $normalizedSymbols = [];

    foreach ($parsedSymbols as $symbol) {
        $name = $symbol['name'] ?? null;
        if ($name === null || $name === '') {
            continue;
        }
        $normalizedSymbols[] = [
            'name' => $name,
            'score' => isset($symbol['score']) ? (float)$symbol['score'] : 0.0
        ];
    }

    usort($normalizedSymbols, function ($a, $b) {
        return $b['score'] <=> $a['score'];
    });

    $virusSymbols = ['ESET_VIRUS', 'CLAM_VIRUS'];
    $badAttachmentSymbols = ['BAD_ATTACHMENT_EXT', 'BAD_ATTACHEMENT_EXT'];
    $statusSymbolGroups = [
        'virus' => ['CLAM_VIRUS', 'ESET_VIRUS'],
        'bad-extension' => ['BAD_FILE_EXT', 'ARCHIVE_WITH_EXECUTABLE'],
        'blacklist' => ['BLACKLIST_IP', 'BLACKLIST_EMAIL_SMTP', 'BLACKLIST_EMAIL_MIME'],
        'whitelist' => ['WHITELIST_IP', 'WHITELIST_EMAIL_MIME', 'WHITELIST_EMAIL_SMTP'],
    ];

    $statusSymbolMatches = [
        'virus' => [],
        'bad-extension' => [],
        'blacklist' => [],
        'whitelist' => [],
    ];

    $hasVirusSymbol = false;
    $hasBadAttachmentSymbol = false;

    foreach ($normalizedSymbols as $symbol) {
        $name = $symbol['name'];
        if (in_array($name, $virusSymbols, true)) {
            $hasVirusSymbol = true;
        }
        if (in_array($name, $badAttachmentSymbols, true)) {
            $hasBadAttachmentSymbol = true;
        }
        foreach ($statusSymbolGroups as $groupKey => $groupSymbols) {
            if (in_array($name, $groupSymbols, true)) {
                $statusSymbolMatches[$groupKey][] = substr($name,0,10);
            }
        }
    }

    foreach ($statusSymbolMatches as $groupKey => $groupSymbols) {
        $statusSymbolMatches[$groupKey] = array_values(array_unique($groupSymbols));
    }

    return [
        'parsed_symbols' => $normalizedSymbols,
        'has_virus_symbol' => $hasVirusSymbol,
        'has_bad_attachment_symbol' => $hasBadAttachmentSymbol,
        'status_symbol_matches' => $statusSymbolMatches,
    ];
}

function getStatusRowClass(array $statusSymbolMatches): string {
    $priority = ['virus', 'bad-extension', 'blacklist', 'whitelist'];
    foreach ($priority as $statusKey) {
        if (!empty($statusSymbolMatches[$statusKey])) {
            return 'status-row-' . $statusKey;
        }
    }
    return '';
}

/**
 * Get top symbols with scores from trace
 */
function getTopSymbols($db, $dateFrom, $dateTo, $domainFilter, $params, $limit = 20) {
    $domainFilterTrace = str_replace(['sender', 'recipients'], ['mt.sender', 'mt.recipients'], $domainFilter);
    $sql = "SELECT symbols
            FROM message_trace mt
            WHERE timestamp BETWEEN ? AND ?
            AND ($domainFilterTrace)
            AND symbols IS NOT NULL
            AND symbols != ''";

    $stmt = $db->prepare($sql);
    $stmt->execute(array_merge([$dateFrom, $dateTo], $params));

    $symbolStats = [];
    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $parsedSymbols = parseSymbolsForStats($row['symbols']);
        foreach ($parsedSymbols as $symbol) {
            $name = $symbol['name'];
            $score = $symbol['score'];
            if (!isset($symbolStats[$name])) {
                $symbolStats[$name] = [
                    'count' => 0,
                    'total_score' => 0.0,
                    'max_score' => $score
                ];
            }
            $symbolStats[$name]['count']++;
            $symbolStats[$name]['total_score'] += $score;
            if ($score > $symbolStats[$name]['max_score']) {
                $symbolStats[$name]['max_score'] = $score;
            }
        }
    }

    $symbols = [];
    foreach ($symbolStats as $name => $data) {
        $symbols[] = [
            'symbol' => $name,
            'count' => $data['count'],
            'avg_score' => $data['count'] > 0 ? $data['total_score'] / $data['count'] : 0.0,
            'max_score' => $data['max_score']
        ];
    }

    usort($symbols, function ($a, $b) {
        if ($b['count'] === $a['count']) {
            return $b['avg_score'] <=> $a['avg_score'];
        }
        return $b['count'] <=> $a['count'];
    });

    return array_slice($symbols, 0, $limit);
}

/**
 * Get antivirus type stats from symbol options.
 */
function getAntivirusTypeStats($db, $dateFrom, $dateTo, $domainFilter, $params, $limit = 20) {
    $sql = "SELECT symbols
            FROM quarantine_messages
            WHERE timestamp BETWEEN ? AND ?
            AND ($domainFilter)
            AND symbols IS NOT NULL
            AND symbols != ''";

    $stmt = $db->prepare($sql);
    $stmt->execute(array_merge([$dateFrom, $dateTo], $params));

    $virusSymbols = ['ESET_VIRUS', 'CLAM_VIRUS'];
    $virusStats = [];
    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $entries = parseSymbolsWithOptions($row['symbols']);
        foreach ($entries as $entry) {
            $name = $entry['name'] ?? '';
            if (!in_array($name, $virusSymbols, true)) {
                continue;
            }
            $options = $entry['options'] ?? [];
            if (empty($options)) {
                $options = ['__unknown__'];
            }
            foreach ($options as $option) {
                $optionKey = trim((string)$option);
                if ($optionKey === '') {
                    $optionKey = '__unknown__';
                }
                if (!isset($virusStats[$optionKey])) {
                    $virusStats[$optionKey] = [
                        'virus_type' => $optionKey,
                        'count' => 0,
                        'symbols' => []
                    ];
                }
                $virusStats[$optionKey]['count']++;
                $virusStats[$optionKey]['symbols'][$name] = true;
            }
        }
    }

    $results = [];
    foreach ($virusStats as $data) {
        $results[] = [
            'virus_type' => $data['virus_type'],
            'count' => $data['count'],
            'symbols' => array_keys($data['symbols'])
        ];
    }

    usort($results, function ($a, $b) {
        if ($a['count'] === $b['count']) {
            return strcmp((string)$a['virus_type'], (string)$b['virus_type']);
        }
        return $b['count'] <=> $a['count'];
    });

    return array_slice($results, 0, $limit);
}


/**
 * Search symbols with scores for admin analysis
 */
function search_symbols($db, $search, $dateFrom = null, $dateTo = null, $limit = 50) {
    if (!checkPermission('admin')) {
        return [];
    }

    $search = trim((string)$search);
    if ($search === '') {
        return [];
    }

    $params = [];
    $where = [
        "symbols IS NOT NULL",
        "symbols != ''",
        "symbols LIKE ?"
    ];
    $params[] = '%' . $search . '%';

    if ($dateFrom && $dateTo) {
        $where[] = "timestamp BETWEEN ? AND ?";
        $params[] = $dateFrom;
        $params[] = $dateTo;
    }

    $sql = "SELECT symbols
            FROM message_trace
            WHERE " . implode(' AND ', $where);

    $stmt = $db->prepare($sql);
    $stmt->execute($params);

    $symbolStats = [];
    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $parsedSymbols = parseSymbolsForStats($row['symbols']);
        foreach ($parsedSymbols as $symbol) {
            $name = $symbol['name'];
            if (stripos($name, $search) === false) {
                continue;
            }
            $score = $symbol['score'];
            if (!isset($symbolStats[$name])) {
                $symbolStats[$name] = [
                    'count' => 0,
                    'total_score' => 0.0,
                    'max_score' => $score,
                    'min_score' => $score
                ];
            }
            $symbolStats[$name]['count']++;
            $symbolStats[$name]['total_score'] += $score;
            if ($score > $symbolStats[$name]['max_score']) {
                $symbolStats[$name]['max_score'] = $score;
            }
            if ($score < $symbolStats[$name]['min_score']) {
                $symbolStats[$name]['min_score'] = $score;
            }
        }
    }

    $symbols = [];
    foreach ($symbolStats as $name => $data) {
        $symbols[] = [
            'symbol' => $name,
            'count' => $data['count'],
            'avg_score' => $data['count'] > 0 ? $data['total_score'] / $data['count'] : 0.0,
            'max_score' => $data['max_score'],
            'min_score' => $data['min_score']
        ];
    }

    usort($symbols, function ($a, $b) {
        if ($b['count'] === $a['count']) {
            return $b['avg_score'] <=> $a['avg_score'];
        }
        return $b['count'] <=> $a['count'];
    });

    return array_slice($symbols, 0, $limit);
}

/**
 * Search symbols with scores for current user scope (admin/domain admin).
 */
function searchSymbolsWithStats($db, $search, $dateFrom, $dateTo, $domainFilter, $params, $limit = 50) {
    $search = trim((string)$search);
    if ($search === '') {
        return [];
    }

    $domainFilterTrace = str_replace(['sender', 'recipients'], ['mt.sender', 'mt.recipients'], $domainFilter);
    $sql = "SELECT mt.symbols
            FROM message_trace mt
            WHERE mt.timestamp BETWEEN ? AND ?
            AND ($domainFilterTrace)
            AND mt.symbols IS NOT NULL
            AND mt.symbols != ''
            AND mt.symbols LIKE ?";

    $stmt = $db->prepare($sql);
    $stmt->execute(array_merge([$dateFrom, $dateTo], $params, ['%' . $search . '%']));

    $symbolStats = [];
    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $parsedSymbols = parseSymbolsForStats($row['symbols']);
        foreach ($parsedSymbols as $symbol) {
            $name = $symbol['name'];
            if (stripos($name, $search) === false) {
                continue;
            }
            $score = $symbol['score'];
            if (!isset($symbolStats[$name])) {
                $symbolStats[$name] = [
                    'count' => 0,
                    'total_score' => 0.0,
                    'max_score' => $score,
                    'min_score' => $score
                ];
            }
            $symbolStats[$name]['count']++;
            $symbolStats[$name]['total_score'] += $score;
            if ($score > $symbolStats[$name]['max_score']) {
                $symbolStats[$name]['max_score'] = $score;
            }
            if ($score < $symbolStats[$name]['min_score']) {
                $symbolStats[$name]['min_score'] = $score;
            }
        }
    }

    $symbols = [];
    foreach ($symbolStats as $name => $data) {
        $symbols[] = [
            'symbol' => $name,
            'count' => $data['count'],
            'avg_score' => $data['count'] > 0 ? $data['total_score'] / $data['count'] : 0.0,
            'max_score' => $data['max_score'],
            'min_score' => $data['min_score']
        ];
    }

    usort($symbols, function ($a, $b) {
        if ($b['count'] === $a['count']) {
            return $b['avg_score'] <=> $a['avg_score'];
        }
        return $b['count'] <=> $a['count'];
    });

    return array_slice($symbols, 0, $limit);
}

/**
 * Get message trace entries matching a specific symbol.
 */
function getSymbolMessages($db, $symbol, $dateFrom, $dateTo, $domainFilter, $params, $limit = 100) {
    $symbol = trim((string)$symbol);
    if ($symbol === '') {
        return [];
    }

    $domainFilterTrace = str_replace(['sender', 'recipients'], ['mt.sender', 'mt.recipients'], $domainFilter);
    $sql = "SELECT mt.id, mt.timestamp, mt.sender, mt.recipients, mt.subject, mt.action, mt.score, mt.symbols
            FROM message_trace mt
            WHERE mt.timestamp BETWEEN ? AND ?
            AND ($domainFilterTrace)
            AND mt.symbols IS NOT NULL
            AND mt.symbols != ''
            AND mt.symbols LIKE ?
            ORDER BY mt.timestamp DESC
            LIMIT ?";

    $stmt = $db->prepare($sql);
    $stmt->execute(array_merge([$dateFrom, $dateTo], $params, ['%' . $symbol . '%', (int)$limit]));

    $messages = [];
    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $symbolScore = null;
        $parsedSymbols = parseSymbolsForStats($row['symbols']);
        foreach ($parsedSymbols as $symbolEntry) {
            if (strcasecmp($symbolEntry['name'], $symbol) === 0) {
                $symbolScore = $symbolEntry['score'];
                break;
            }
        }
        if ($symbolScore === null) {
            continue;
        }
        $row['symbol_score'] = $symbolScore;
        $messages[] = $row;
    }

    return $messages;
}

/**
 * Get volume and count statistics
 */
function getVolumeStats($db, $dateFrom, $dateTo, $domainFilter, $params) {
    // Quarantine stats
    $sql = "SELECT 
                COUNT(*) as total_messages,
                SUM(LENGTH(message_content)) as total_bytes,
                AVG(score) as avg_score,
                MIN(score) as min_score,
                MAX(score) as max_score
            FROM quarantine_messages
            WHERE timestamp BETWEEN ? AND ?
            AND ($domainFilter)";

    $stmt = $db->prepare($sql);
    $stmt->execute(array_merge([$dateFrom, $dateTo], $params));
    $quarantine = $stmt->fetch(PDO::FETCH_ASSOC);

    // Trace stats - replace sender/recipients with mt. prefix
    $domainFilterTrace = str_replace(['sender', 'recipients'], ['mt.sender', 'mt.recipients'], $domainFilter);
    $sql = "SELECT 
                COUNT(*) as total_messages,
                SUM(size_bytes) as total_bytes,
                AVG(score) as avg_score
            FROM message_trace mt
            WHERE timestamp BETWEEN ? AND ?
            AND ($domainFilterTrace)";

    $stmt = $db->prepare($sql);
    $stmt->execute(array_merge([$dateFrom, $dateTo], $params));
    $trace = $stmt->fetch(PDO::FETCH_ASSOC);

    return [
        'quarantine' => $quarantine,
        'trace' => $trace
    ];
}

/**
 * Get action distribution from message trace
 */
function getActionDistribution($db, $dateFrom, $dateTo, $domainFilter, $params) {
    $domainFilterTrace = str_replace(['sender', 'recipients'], ['mt.sender', 'mt.recipients'], $domainFilter);
    $sql = "SELECT 
                action,
                COUNT(*) as count,
                AVG(score) as avg_score
            FROM message_trace mt
            WHERE timestamp BETWEEN ? AND ?
            AND ($domainFilterTrace)
            GROUP BY action
            ORDER BY count DESC";

    $stmt = $db->prepare($sql);
    $stmt->execute(array_merge([$dateFrom, $dateTo], $params));
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

/**
 * Get state distribution from quarantine
 */
function getStateDistribution($db, $dateFrom, $dateTo, $domainFilter, $params) {
    $sql = "SELECT 
                CASE 
                    WHEN state = 0 THEN 'Quarantined'
                    WHEN state = 1 THEN 'Learned HAM'
                    WHEN state = 2 THEN 'Learned SPAM'
                    WHEN state = 3 THEN 'Released'
                    ELSE 'Unknown'
                END as state_name,
                state,
                COUNT(*) as count,
                AVG(score) as avg_score
            FROM quarantine_messages
            WHERE timestamp BETWEEN ? AND ?
            AND ($domainFilter)
            GROUP BY state
            ORDER BY count DESC";

    $stmt = $db->prepare($sql);
    $stmt->execute(array_merge([$dateFrom, $dateTo], $params));
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

/**
 * Get daily trace data for charts
 */
function getDailyTrace($db, $dateFrom, $dateTo, $domainFilter, $params) {
    $domainFilterTrace = str_replace(['sender', 'recipients'], ['mt.sender', 'mt.recipients'], $domainFilter);
    $sql = "SELECT 
                DATE(timestamp) as date,
                action,
                COUNT(*) as count,
                AVG(score) as avg_score
            FROM message_trace mt
            WHERE timestamp BETWEEN ? AND ?
            AND ($domainFilterTrace)
            GROUP BY DATE(timestamp), action
            ORDER BY date ASC, action";

    $stmt = $db->prepare($sql);
    $stmt->execute(array_merge([$dateFrom, $dateTo], $params));
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

/**
 * Get weekly trace data for charts
 */
function getWeeklyTrace($db, $dateFrom, $dateTo, $domainFilter, $params) {
    $domainFilterTrace = str_replace(['sender', 'recipients'], ['mt.sender', 'mt.recipients'], $domainFilter);
    $sql = "SELECT 
                YEARWEEK(timestamp, 1) as week,
                DATE(DATE_SUB(timestamp, INTERVAL WEEKDAY(timestamp) DAY)) as week_start,
                action,
                COUNT(*) as count,
                AVG(score) as avg_score
            FROM message_trace mt
            WHERE timestamp BETWEEN ? AND ?
            AND ($domainFilterTrace)
            GROUP BY YEARWEEK(timestamp, 1), action
            ORDER BY week ASC, action";

    $stmt = $db->prepare($sql);
    $stmt->execute(array_merge([$dateFrom, $dateTo], $params));
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

// ============================================
// Rspamd map management helpers
// ============================================

if (!function_exists('getRspamdApiServers')) {
    function getRspamdApiServers() {
        if (defined('RSPAMD_API_SERVERS') && is_array(RSPAMD_API_SERVERS) && !empty(RSPAMD_API_SERVERS)) {
            return RSPAMD_API_SERVERS;
        }

        if (defined('RSPAMD_API_URL') && !empty(RSPAMD_API_URL)) {
            return [RSPAMD_API_URL];
        }

        return [];
    }
}

if (!function_exists('getRspamdMapName')) {
    function getRspamdMapName($listType, $entryType) {
        $defaultMaps = [
            'whitelist' => [
                'ip' => 'whitelist_ip',
                'email' => 'whitelist_email',
                'email_regex' => 'whitelist_email_regex',
                'subject' => 'wl_subject_regex',
            ],
            'blacklist' => [
                'ip' => 'blacklist_ip',
                'email' => 'blacklist_email',
                'email_regex' => 'blacklist_email_regex',
                'subject' => 'bl_subject_regex',
            ],
        ];

        if (defined('RSPAMD_MAPS') && is_array(RSPAMD_MAPS)) {
            if (isset(RSPAMD_MAPS[$listType][$entryType])) {
                return RSPAMD_MAPS[$listType][$entryType];
            }
        }

        return $defaultMaps[$listType][$entryType] ?? null;
    }
}

if (!function_exists('buildRspamdMapContent')) {
    function buildRspamdMapContent(array $entries) {
        $lines = [];
        foreach ($entries as $entry) {
            $value = str_replace(["\r", "\n"], '', $entry['entry_value']);
            $lines[] = trim($value);
        }

        return implode("\n", $lines) . "\n";
    }
}

if (!function_exists('isRegexMapEntry')) {
    function isRegexMapEntry(string $value): bool {
        $value = trim($value);

        if ($value === '' || $value[0] !== '/') {
            return false;
        }

        $lastSlash = strrpos($value, '/');
        if ($lastSlash === 0) {
            return false;
        }

        $match = @preg_match($value, '');

        return $match !== false && preg_last_error() === PREG_NO_ERROR;
    }
}

if (!function_exists('isValidMapEmailEntry')) {
    function isValidMapEmailEntry(string $value): bool {
        if (filter_var($value, FILTER_VALIDATE_EMAIL) !== false) {
            return true;
        }

        if (preg_match('/^@(.+)$/', $value, $matches)) {
            return filter_var($matches[1], FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) !== false;
        }

        return false;
    }
}

if (!function_exists('canManageEmailMapEntry')) {
    function canManageEmailMapEntry(string $entryValue): bool {
        $userRole = $_SESSION['user_role'] ?? 'viewer';

        if ($userRole === 'admin') {
            return true;
        }

        if ($userRole !== 'domain_admin') {
            return false;
        }

        if (checkDomainAccess($entryValue)) {
            return true;
        }

        if (!isRegexMapEntry($entryValue)) {
            return false;
        }

        $userDomains = $_SESSION['user_domains'] ?? [];
        if (empty($userDomains)) {
            return false;
        }

        foreach ($userDomains as $domain) {
            $probe = 'test@' . $domain;
            if (@preg_match($entryValue, $probe) === 1) {
                return true;
            }
        }

        return false;
    }
}

/**
 * Get whitelist/blacklist status for sender emails.
 *
 * @param PDO $db Database connection
 * @param array $emails List of email addresses
 * @return array ['whitelist' => [email => true], 'blacklist' => [email => true]]
 */
function getEmailMapStatus($db, array $emails): array {
    $normalized = array_values(array_unique(array_filter(array_map(function ($email) {
        return strtolower(trim((string)$email));
    }, $emails))));

    if (empty($normalized)) {
        return ['whitelist' => [], 'blacklist' => []];
    }

    $placeholders = implode(',', array_fill(0, count($normalized), '?'));
    $sql = "
        SELECT list_type, LOWER(entry_value) AS entry_value
        FROM rspamd_map_entries
        WHERE entry_type = 'email'
          AND LOWER(entry_value) IN ($placeholders)
    ";
    $stmt = $db->prepare($sql);
    $stmt->execute($normalized);

    $whitelist = [];
    $blacklist = [];
    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        if ($row['list_type'] === 'whitelist') {
            $whitelist[$row['entry_value']] = true;
        } elseif ($row['list_type'] === 'blacklist') {
            $blacklist[$row['entry_value']] = true;
        }
    }

    return ['whitelist' => $whitelist, 'blacklist' => $blacklist];
}

if (!function_exists('uploadRspamdMap')) {
    function uploadRspamdMap($mapName, $content) {
        $servers = getRspamdApiServers();
        if (empty($servers)) {
            return [
                'success' => false,
                'error' => 'Rspamd API není nakonfigurováno',
                'results' => [],
            ];
        }

        $results = [];
        $success = true;

        foreach ($servers as $server) {
            $password = defined('RSPAMD_API_PASSWORD') ? RSPAMD_API_PASSWORD : '';

            // KROK 1: Získej seznam map
            $mapsUrl = rtrim($server, '/') . '/maps';
            $ch = curl_init($mapsUrl);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 10);
            curl_setopt($ch, CURLOPT_HTTPHEADER, ['Password: ' . $password]);

            $mapsResponse = curl_exec($ch);
            $mapsHttpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($mapsHttpCode !== 200) {
                $results[] = [
                    'server' => $server,
                    'error' => 'Nelze načíst seznam map (HTTP ' . $mapsHttpCode . ')',
                    'success' => false,
                ];
                $success = false;
                continue;
            }

                $maps = json_decode($mapsResponse, true);
                if (!is_array($maps)) {
                $results[] = [
                    'server' => $server,
                    'error' => 'Neplatná odpověď API pro seznam map',
                    'success' => false,
                            ];
                $success = false;
                                    continue;
                                }

            // KROK 2: Najdi ID mapy
            $mapId = null;
            $mapUri = null;
            $mapEditable = false;

            foreach ($maps as $map) {
                if (!is_array($map)) {
                    continue;
                                }

                $uri = $map['uri'] ?? '';

                // Hledej přesnou shodu s .map souborem
                if (strpos($uri, $mapName . '.map') !== false) {
                    $isEditable = ($map['editable'] ?? false) === true;

                    // Preferuj editovatelné mapy ve /var/lib/rspamd/
                    if ($isEditable && strpos($uri, '/var/lib/rspamd/') !== false) {
                        $mapId = $map['map'];
                        $mapUri = $uri;
                        $mapEditable = true;
                        break;  // Perfektní match, ukonči
                    } elseif ($isEditable && $mapId === null) {
                        $mapId = $map['map'];
                        $mapUri = $uri;
                        $mapEditable = true;
                        // Pokračuj hledat /var/lib/rspamd/ verzi
                            }
                            }
                        }

            if ($mapId === null) {
                $results[] = [
                    'server' => $server,
                    'error' => "Mapa '{$mapName}.map' nebyla nalezena.",
                    'hint' => "Zkontroluj: 1) Existuje /var/lib/rspamd/{$mapName}.map? 2) Je v /etc/rspamd/local.d/multimap.conf? 3) Byl Rspamd restartován?",
                    'success' => false,
                    'available_maps' => array_values(array_filter(
                        array_map(function($m) {
                            $uri = $m['uri'] ?? '';
                            // Ukaž jen custom mapy (ne vestavěné)
                            if (strpos($uri, '/var/lib/rspamd/') !== false || 
                                (strpos($uri, '.map') !== false && 
                                 strpos($uri, 'whitelist') === false && 
                                 strpos($uri, 'blacklist') === false)) {
                                return basename($uri);
                    }
                            return null;
                        }, $maps)
                    )),
                ];
                $success = false;
                continue;
                }

            if (!$mapEditable) {
                $results[] = [
                    'server' => $server,
                    'error' => "Mapa '{$mapName}' (ID: $mapId) není editovatelná",
                    'hint' => "Mapa musí být v /var/lib/rspamd/, ne v /etc/rspamd/",
                    'map_uri' => $mapUri,
                    'success' => false,
                ];
                $success = false;
                continue;
            }

            $content = trim($content);
            if (empty($content)) {
                // Rspamd nemá rád úplně prázdné soubory u některých typů map
                // Lepší je tam nechat aspoň komentář
                $content = "# Empty map\n";
            } else {
                // Zajisti, že končí novým řádkem
                $content .= "\n";
            }

            // KROK 3: Ulož data
            $saveUrl = rtrim($server, '/') . '/savemap';
            $ch = curl_init($saveUrl);
            
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $content);             
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 10);
            curl_setopt($ch, CURLOPT_HTTPHEADER, [
                "Map-Id: " . (string)$mapId, // ID z předchozího kroku
                "Map: " . (string)$mapId, // ID z předchozího kroku
                'Password: ' . $password,
                'Content-Type: text/plain', // Rspamd přijímá raw text
                "Content-Length: " . strlen($content) 
            ]);

            $response = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $curlError = curl_error($ch);
            curl_close($ch);

            $serverSuccess = ($httpCode >= 200 && $httpCode < 300 && !$curlError);

            $results[] = [
                'server' => $server,
                'map_id' => $mapId,
                'map_uri' => $mapUri,
                'map_name' => $mapName,
                'http_code' => $httpCode,
                'response' => $response,
                'error' => $curlError ?: null,
                'success' => $serverSuccess,
                'data_size' => strlen($content),
            ];

            if (!$serverSuccess) {
                $success = false;
            }
        }

        return [
            'success' => $success,
            'results' => $results,
        ];
    }
}

?>
