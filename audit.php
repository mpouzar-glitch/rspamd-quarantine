<?php
/**
 * Audit Log - Rspamd Quarantine
 * Zobrazení audit logu akcí uživatelů
 */

session_start();
require_once 'config.php';
require_once 'functions.php';
require_once 'filter_helper.php';

// Authentication check
if (!isAuthenticated()) {
    header('Location: login.php');
    exit;
}

$db = Database::getInstance()->getConnection();
$userRole = $_SESSION['user_role'] ?? 'viewer';
$user = $_SESSION['username'] ?? 'unknown';

// Pouze admin a domainadmin mohou vidět audit log
if (!checkPermission('admin')) {
    $_SESSION['error_msg'] = 'Nemáte oprávnění k přístupu k audit logu.';
    header('Location: index.php');
    exit;
}

// Get filters from request
$filters = [
    'search' => $_GET['search'] ?? '',
    'action' => $_GET['action'] ?? '',
    'username' => $_GET['username'] ?? '',
    'date_from' => $_GET['date_from'] ?? '',
    'date_to' => $_GET['date_to'] ?? '',
];

// Pagination
$page = isset($_GET['page']) ? max(1, (int)$_GET['page']) : 1;
$offset = ($page - 1) * ITEMS_PER_PAGE;

// Build query
$params = [];
$where = ['1=1'];

// Admin vidí vše
if ($userRole === 'admin') {
    $where[] = 'username = ?';
    $params[] = $user;
}

// Apply filters
if (!empty($filters['search'])) {
    $search = '%' . $filters['search'] . '%';
    $where[] = '(username LIKE ? OR action LIKE ? OR details LIKE ? OR ip_address LIKE ?)';
    $params[] = $search;
    $params[] = $search;
    $params[] = $search;
    $params[] = $search;
}

if (!empty($filters['action'])) {
    $where[] = 'action = ?';
    $params[] = $filters['action'];
}

if (!empty($filters['username'])) {
    $where[] = 'username LIKE ?';
    $params[] = '%' . $filters['username'] . '%';
}

if (!empty($filters['date_from'])) {
    $where[] = 'timestamp >= ?';
    $params[] = $filters['date_from'] . ' 00:00:00';
}

if (!empty($filters['date_to'])) {
    $where[] = 'timestamp <= ?';
    $params[] = $filters['date_to'] . ' 23:59:59';
}

// Count total
$countSql = 'SELECT COUNT(*) FROM audit_log WHERE ' . implode(' AND ', $where);
$countStmt = $db->prepare($countSql);
$countStmt->execute($params);
$totalItems = (int)$countStmt->fetchColumn();
$totalPages = max(1, (int)ceil($totalItems / ITEMS_PER_PAGE));

// Get records
$sql = 'SELECT id, user_id, username, action, entity_type, entity_id, details, ip_address, timestamp 
        FROM audit_log 
        WHERE ' . implode(' AND ', $where) . '
        ORDER BY timestamp DESC 
        LIMIT ' . ITEMS_PER_PAGE . ' OFFSET ' . $offset;

$stmt = $db->prepare($sql);
$stmt->execute($params);
$records = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Get statistics
$statsSql = 'SELECT 
    COUNT(*) as total,
    COUNT(DISTINCT username) as unique_users,
    SUM(CASE WHEN action LIKE "release%" THEN 1 ELSE 0 END) as releases,
    SUM(CASE WHEN action LIKE "learn%" THEN 1 ELSE 0 END) as learns,
    SUM(CASE WHEN action LIKE "delete%" THEN 1 ELSE 0 END) as deletes,
    SUM(CASE WHEN action = "login_success" THEN 1 ELSE 0 END) as logins
    FROM audit_log 
    WHERE ' . implode(' AND ', $where);

$statsStmt = $db->prepare($statsSql);
$statsStmt->execute($params);
$stats = $statsStmt->fetch(PDO::FETCH_ASSOC);

$pageTitle = 'Audit Log - Rspamd Quarantine';
include 'menu.php';
?>
<!DOCTYPE html>
<html lang="cs">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($pageTitle); ?></title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link rel="stylesheet" href="css/style.css">
    <link rel="stylesheet" href="css/stats-inline.css">
    <link rel="stylesheet" href="css/audit.css">
</head>
<body>

<div class="container">

    <!-- NADPIS SE STATISTIKAMI -->
    <div class="header-with-stats">
        <div class="header-title">
            <h1><i class="fas fa-clipboard-list"></i> Audit Log</h1>
        </div>
        <div class="stats-inline">
            <div class="stat-inline-item total">
                <span class="stat-inline-label">Celkem</span>
                <span class="stat-inline-value"><?php echo number_format($stats['total']); ?></span>
            </div>
            <div class="stat-inline-item" style="border-left-color: #17a2b8;">
                <span class="stat-inline-label">Uvolněno</span>
                <span class="stat-inline-value"><?php echo number_format($stats['releases']); ?></span>
            </div>
            <div class="stat-inline-item" style="border-left-color: #e74c3c;">
                <span class="stat-inline-label">Naučeno</span>
                <span class="stat-inline-value"><?php echo number_format($stats['learns']); ?></span>
            </div>
            <div class="stat-inline-item" style="border-left-color: #6c757d;">
                <span class="stat-inline-label">Smazáno</span>
                <span class="stat-inline-value"><?php echo number_format($stats['deletes']); ?></span>
            </div>
            <div class="stat-inline-item" style="border-left-color: #9b59b6;">
                <span class="stat-inline-label">Uživatelé</span>
                <span class="stat-inline-value"><?php echo number_format($stats['unique_users']); ?></span>
            </div>
        </div>
    </div>

    <?php displayAlerts(); ?>

    <!-- FILTRY -->
    <?php echo renderAuditFilters($filters); ?>

    <?php if (empty($records)): ?>
        <div class="no-results">
            <i class="fas fa-clipboard-list"></i>
            <h3>Žádné záznamy nenalezeny</h3>
            <p>Zkuste upravit kritéria vyhledávání.</p>
        </div>
    <?php else: ?>

        <div class="results-info">
            Zobrazeno <strong><?php echo count($records); ?></strong> z <strong><?php echo number_format($totalItems); ?></strong> záznamů
            | Stránka <?php echo $page; ?> z <?php echo $totalPages; ?>
        </div>

        <table class="messages-table audit-table">
            <thead>
                <tr>
                    <th style="width: 140px;">Čas</th>
                    <th style="width: 120px;">Uživatel</th>
                    <th style="width: 150px;">Akce</th>
                    <th>Detail</th>
                    <th style="width: 130px;">IP Adresa</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($records as $record): ?>
                    <?php
                    $timestamp = date('d.m. H:i:s', strtotime($record['timestamp']));
                    $action = $record['action'];

                    // Determine action badge class
                    if (strpos($action, 'release') !== false) {
                        $actionClass = 'action-release';
                        $actionIcon = 'fa-paper-plane';
                    } elseif (strpos($action, 'learn_spam') !== false) {
                        $actionClass = 'action-learn-spam';
                        $actionIcon = 'fa-ban';
                    } elseif (strpos($action, 'learn_ham') !== false) {
                        $actionClass = 'action-learn-ham';
                        $actionIcon = 'fa-check';
                    } elseif (strpos($action, 'delete') !== false) {
                        $actionClass = 'action-delete';
                        $actionIcon = 'fa-trash';
                    } elseif (strpos($action, 'login') !== false) {
                        $actionClass = 'action-login';
                        $actionIcon = 'fa-sign-in-alt';
                    } else {
                        $actionClass = 'action-default';
                        $actionIcon = 'fa-circle';
                    }

                    // Format action name
                    $actionName = str_replace('_', ' ', ucfirst($action));
                    ?>
                    <tr>
                        <td class="timestamp"><?php echo htmlspecialchars($timestamp); ?></td>
                        <td class="username-cell"><?php echo htmlspecialchars($record['username']); ?></td>
                        <td>
                            <span class="action-badge <?php echo $actionClass; ?>">
                                <i class="fas <?php echo $actionIcon; ?>"></i>
                                <?php echo htmlspecialchars($actionName); ?>
                            </span>
                        </td>
                        <td class="details-cell" title="<?php echo htmlspecialchars($record['details'] ?? ''); ?>">
                            <?php echo htmlspecialchars($record['details'] ?? '-'); ?>
                        </td>
                        <td class="ip-address"><?php echo htmlspecialchars($record['ip_address'] ?? '-'); ?></td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>

        <!-- Pagination -->
        <?php if ($totalPages > 1): ?>
            <div class="pagination">
                <?php if ($page > 1): ?>
                    <a href="?page=<?php echo ($page - 1); ?>&<?php echo http_build_query(array_diff_key($_GET, ['page' => ''])); ?>" class="page-link">
                        <i class="fas fa-chevron-left"></i> Předchozí
                    </a>
                <?php endif; ?>

                <?php
                $start = max(1, $page - 3);
                $end = min($totalPages, $page + 3);
                for ($i = $start; $i <= $end; $i++):
                    $activeClass = ($i === $page) ? 'active' : '';
                ?>
                    <a href="?page=<?php echo $i; ?>&<?php echo http_build_query(array_diff_key($_GET, ['page' => ''])); ?>" 
                       class="page-link <?php echo $activeClass; ?>">
                        <?php echo $i; ?>
                    </a>
                <?php endfor; ?>

                <?php if ($page < $totalPages): ?>
                    <a href="?page=<?php echo ($page + 1); ?>&<?php echo http_build_query(array_diff_key($_GET, ['page' => ''])); ?>" class="page-link">
                        Další <i class="fas fa-chevron-right"></i>
                    </a>
                <?php endif; ?>
            </div>
        <?php endif; ?>
    <?php endif; ?>
</div>
<?php include 'footer.php'; ?>
</body>
</html>
