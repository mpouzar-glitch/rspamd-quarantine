<?php
/**
 * Rspamd Quarantine - Helper Functions
 * Version: 2.0.2
 * Updated: 2026-01-01
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
        'domain_admin' => 2,
        'admin' => 3
    ];

    $required_level = $roles_hierarchy[$required_role] ?? 0;
    $user_level = $roles_hierarchy[$user_role] ?? 0;

    return $user_level >= $required_level;
}

// ============================================
// Domain Access Functions
// ============================================

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

    // Viewer has no access
    return false;
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

    // Viewer sees nothing by default
    return '1=0';
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

    // Remove quotes
    $header = trim($header, '"\'');

    // Try mb_decode_mimeheader first
    $decoded = mb_decode_mimeheader($header);

    // If still contains encoded parts, try iconv_mime_decode
    if (preg_match('/=\?[^?]+\?[BQ]\?[^?]+\?=/i', $decoded)) {
        $decoded = iconv_mime_decode($decoded, ICONV_MIME_DECODE_CONTINUE_ON_ERROR, 'UTF-8');
    }

    return $decoded ?: $header;
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
        $where[] = "(sender LIKE ? OR recipients LIKE ? OR subject LIKE ? OR message_id LIKE ?)";
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
        $where[] = "sender LIKE ?";
        $params[] = '%' . $filters['sender'] . '%';
    }

    // Recipient filter
    if (!empty($filters['recipient'])) {
        $where[] = "recipients LIKE ?";
        $params[] = '%' . $filters['recipient'] . '%';
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
        'select' => 'id, message_id, timestamp, sender, recipients, subject, action, score, state, state_at, state_by',
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
            hostname
        FROM message_trace
        WHERE " . implode(' AND ', $where) . "
        ORDER BY timestamp DESC
    ";

    if (isset($options['limit'])) {
        $sql .= " LIMIT " . (int)$options['limit'];
    }

    if (isset($options['offset'])) {
        $sql .= " OFFSET " . (int)$options['offset'];
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

?>
