<?php
/**
 * Rspamd Quarantine - Main Index
 * Updated: Compact table, state colors, preview tooltip, icon-only buttons, clickable emails
 */

session_start(); 
require_once 'config.php';
require_once 'filter_helper.php';

// Authentication check
if (!isAuthenticated()) {
    header('Location: login.php');
    exit;
}

$db = Database::getInstance()->getConnection();
$userRole = $_SESSION['user_role'] ?? 'viewer';
$user = $_SESSION['username'] ?? 'unknown';

// Get filters from request
$filters = getFiltersFromRequest();

// Pagination
$page = isset($_GET['page']) ? max(1, (int)$_GET['page']) : 1;
$offset = ($page - 1) * ITEMS_PER_PAGE;

// Get total count
$totalItems = countQuarantineMessages($db, $filters);
$totalPages = max(1, (int)ceil($totalItems / ITEMS_PER_PAGE));

// Build and execute query
$params = [];
$sql = buildQuarantineQuery($filters, $params, [
    'limit' => ITEMS_PER_PAGE,
    'offset' => $offset,
]);

$stmt = $db->prepare($sql);
$stmt->execute($params);
$messages = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Fetch symbols for messages if not included in query
foreach ($messages as &$msg) {
    if (!isset($msg['symbols']) || empty($msg['symbols'])) {
        $symbolStmt = $db->prepare("SELECT symbols FROM quarantine_messages WHERE id = ?");
        $symbolStmt->execute([$msg['id']]);
        $symbolData = $symbolStmt->fetch(PDO::FETCH_ASSOC);
        $msg['symbols'] = $symbolData['symbols'] ?? '';
    }
}
unset($msg); // Break reference


// Get statistics
$stats = getExtendedQuarantineStats($db, $filters);

$pageTitle = 'Karanténa - Rspamd Quarantine';
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
    <link rel="stylesheet" href="css/index.css">
</head>
<body>
    <div class="container">
        <!-- NADPIS SE STATISTIKAMI -->
        <div class="header-with-stats">
            <div class="header-title">
                <h1><i class="fas fa-inbox"></i> Karanténa zpráv</h1>
            </div>
            <div>
                <?php
                echo renderStatsInline($stats, [
                    'show_total' => true,
                    'show_rejected' => true,
                    'show_quarantined' => true,
                    'show_learned_ham' => true,
                    'show_learned_spam' => true,
                    'show_released' => true,
                    'show_avg_score' => true,
                ]);
                ?>
            </div>
        </div>

        <?php displayAlerts(); ?>

        <!-- FILTRY -->
        <?php
        echo renderSearchFilters(getQuarantineFilters([
            'columns' => null,
            'show_search' => true,
            'show_action' => false,
            'show_score_min' => false,
            'show_score_max' => false,
            'show_dates' => true,
            'show_sender' => true,
            'show_recipient' => true,
            'show_state' => true,
            'show_ip' => false,
            'show_auth_user' => false,
            'form_id' => 'filterForm',
            'reset_url' => 'index.php?reset_filters=1',
        ]));
        ?>

        <?php if (empty($messages)): ?>
            <div class="no-results">
                <i class="fas fa-inbox"></i>
                <h3>Žádné zprávy nenalezeny</h3>
                <p>Zkuste upravit kritéria vyhledávání.</p>
            </div>
        <?php else: ?>
            <div class="results-info" style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                    Zobrazeno <strong><?php echo count($messages); ?></strong> z <strong><?php echo number_format($totalItems); ?></strong> zpráv
                    | Stránka <?php echo $page; ?> z <?php echo $totalPages; ?>
                </div>
                <label class="preview-toggle">
                    <input type="checkbox" id="htmlPreviewToggle" onchange="toggleHtmlPreview(this.checked)" style="width: 14px; height: 14px; cursor: pointer;">
                    <i class="fas fa-code"></i> <strong>HTML náhled</strong>
                </label>
            </div>

            <table class="messages-table">
                <thead>
                    <tr>
                        <th style="width: 110px;">Čas</th>
                        <th>Odesílatel</th>
                        <th>Příjemce</th>
                        <th>Předmět</th>
                        <th style="width: 60px;">Skóre</th>
                        <th style="width: 150px;">Operace</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($messages as $msg): ?>
                        <?php
                        $msgId = $msg['id'];
                        $sender = decodeMimeHeader($msg['sender']);
                        $recipients = decodeMimeHeader($msg['recipients']);
                        $subject = decodeMimeHeader($msg['subject']) ?: '(bez předmětu)';
                        $score = round($msg['score'], 2);

                        // Parse symbols from JSON
                        $symbols = $msg['symbols'] ?? '';
                        $parsedSymbols = [];

                        if (!empty($symbols)) {
                            $symbolsData = json_decode($symbols, true);

                            if (is_array($symbolsData)) {
                                foreach ($symbolsData as $symbol) {
                                    if (isset($symbol['name']) && isset($symbol['score'])) {
                                        $parsedSymbols[] = [
                                            'name' => $symbol['name'],
                                            'score' => floatval($symbol['score'])
                                        ];
                                    }
                                }

                                // Sort by score descending
                                usort($parsedSymbols, function($a, $b) {
                                    return $b['score'] <=> $a['score'];
                                });
                            }
                        }
                        $timestamp = date('d.m. H:i', strtotime($msg['timestamp']));

                        // Score class
                        if ($score >= 15) {
                            $scoreClass = 'score-high';
                        } elseif ($score >= 6) {
                            $scoreClass = 'score-medium';
                        } else {
                            $scoreClass = 'score-low';
                        }

                        // State class for row coloring
                        $stateClass = '';
                        switch ((int)$msg['state']) {
                            case 0: $stateClass = 'state-quarantined'; break;
                            case 1: $stateClass = 'state-learned-ham'; break;
                            case 2: $stateClass = 'state-learned-spam'; break;
                            case 3: $stateClass = 'state-released'; break;
                        }

                        // Auto-learn spam detection
                        $autoLearnEnabled = defined('AUTOLEARN_ENABLED') ? AUTOLEARN_ENABLED : false;
                        $autoLearnScore = defined('AUTOLEARN_SCORE') ? AUTOLEARN_SCORE : 15.0;

                        if ($autoLearnEnabled) {
                            $symbols = isset($msg['symbols']) ? $msg['symbols'] : '';
                            $hasAutoLearn = (
                                stripos($symbols, 'BAYES_SPAM') !== false ||
                                stripos($symbols, 'NEURAL_SPAM') !== false ||
                                ($msg['state'] == 0 && $score >= $autoLearnScore)
                            );

                            if ($hasAutoLearn) {
                                $stateClass = 'auto-learn-spam';
                            }
                        }
                        ?>
                        <tr class="message-row <?php echo $stateClass; ?>" id="row_<?php echo $msgId; ?>">
                            <td class="timestamp"><?php echo htmlspecialchars($timestamp); ?></td>
                            <td class="email-field">
                                <i class="fas fa-paper-plane"></i> 
                                <a href="?sender=<?php echo urlencode($sender); ?>" 
                                   class="email-link" 
                                   title="Filtrovat podle odesílatele: <?php echo htmlspecialchars($sender); ?>">
                                    <?php echo htmlspecialchars(truncateText($sender, 40)); ?>
                                </a>
                            </td>
                            <td class="email-field">
                                <i class="fas fa-inbox"></i> 
                                <a href="?recipient=<?php echo urlencode($recipients); ?>" 
                                   class="email-link" 
                                   title="Filtrovat podle příjemce: <?php echo htmlspecialchars($recipients); ?>">
                                    <?php echo htmlspecialchars(truncateText($recipients, 40)); ?>
                                </a>
                            </td>
                            <td class="subject-field">
                                <?php echo htmlspecialchars(truncateText($subject, 70)); ?>
                            </td>
                            <td class="text-center score-cell">
                                <span class="score-badge <?php echo $scoreClass; ?>">
                                    <?php echo $score; ?>

                                    <?php if (!empty($parsedSymbols)): ?>
                                    <div class="symbols-popup">
                                        <div class="symbols-popup-header">
                                            <i class="fas fa-list-ul"></i> Rspamd Symboly (<?php echo count($parsedSymbols); ?>)
                                        </div>
                                        <div class="symbols-grid">
                                            <?php foreach ($parsedSymbols as $sym): 
                                                $symScore = $sym['score'];
                                                $bgcolor = ($symScore >= 1) ? '#e74c3c' : (($symScore > 0) ? '#f39c12' : (($symScore < 0) ? '#27ae60' : '#95a5a6'));
                                            ?>
                                            <span class="symbol-badge" style="background: <?php echo $bgcolor; ?>">
                                                <span class="symbol-name" title="<?php echo htmlspecialchars($sym['name']); ?>">
                                                    <?php echo htmlspecialchars($sym['name']); ?>
                                                </span>
                                                <span class="symbol-score">
                                                    <?php echo number_format($symScore, 2); ?>
                                                </span>
                                            </span>
                                            <?php endforeach; ?>
                                        </div>
                                    </div>
                                    <?php endif; ?>
                                </span>
                            </td>
                            <td class="text-center">
                                <div class="action-controls">
                                    <a href="view.php?id=<?php echo $msgId; ?>" class="action-btn view-btn" title="Zobrazit detail">
                                        <i class="fas fa-eye"></i>
                                    </a>
                                    <form method="POST" action="operations.php" style="display: inline;">
                                        <input type="hidden" name="message_ids" value="<?php echo $msgId; ?>">
                                        <input type="hidden" name="operation" value="learn_spam">
                                        <input type="hidden" name="return_url" value="index.php">
                                        <button type="submit" class="action-btn learn-spam-btn" title="Naučit jako SPAM">
                                            <i class="fas fa-ban"></i>
                                        </button>
                                    </form>
                                    <form method="POST" action="operations.php" style="display: inline;">
                                        <input type="hidden" name="message_ids" value="<?php echo $msgId; ?>">
                                        <input type="hidden" name="operation" value="learn_ham">
                                        <input type="hidden" name="return_url" value="index.php">
                                        <button type="submit" class="action-btn learn-ham-btn" title="Naučit jako HAM">
                                            <i class="fas fa-check"></i>
                                        </button>
                                    </form>
                                    <form method="POST" action="operations.php" style="display: inline;">
                                        <input type="hidden" name="message_ids" value="<?php echo $msgId; ?>">
                                        <input type="hidden" name="operation" value="release">
                                        <input type="hidden" name="return_url" value="index.php">
                                        <button type="submit" class="action-btn release-btn" title="Uvolnit zprávu">
                                            <i class="fas fa-paper-plane"></i>
                                        </button>
                                    </form>
                                    <form method="POST" action="operations.php" style="display: inline;" onsubmit="return confirm('Opravdu smazat zprávu?');">
                                        <input type="hidden" name="message_ids" value="<?php echo $msgId; ?>">
                                        <input type="hidden" name="operation" value="delete">
                                        <input type="hidden" name="return_url" value="index.php">
                                        <button type="submit" class="action-btn delete-btn" title="Smazat zprávu">
                                            <i class="fas fa-trash"></i>
                                        </button>
                                    </form>
                                </div>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>

             <!-- Pagination -->
            <?php if ($totalPages > 1): ?>
                <div class="pagination">
                    <?php if ($page > 1): ?>
                        <a href="?page=<?php echo $page - 1; ?>&<?php echo http_build_query(array_diff_key($_GET, ['page' => ''])); ?>" class="page-link">
                            <i class="fas fa-chevron-left"></i> Předchozí
                        </a>
                    <?php endif; ?>

                    <?php
                    $start = max(1, $page - 3);
                    $end = min($totalPages, $page + 3);
                    for ($i = $start; $i <= $end; $i++):
                        $activeClass = ($i == $page) ? 'active' : '';
                    ?>
                        <a href="?page=<?php echo $i; ?>&<?php echo http_build_query(array_diff_key($_GET, ['page' => ''])); ?>" 
                           class="page-link <?php echo $activeClass; ?>">
                            <?php echo $i; ?>
                        </a>
                    <?php endfor; ?>

                    <?php if ($page < $totalPages): ?>
                        <a href="?page=<?php echo $page + 1; ?>&<?php echo http_build_query(array_diff_key($_GET, ['page' => ''])); ?>" class="page-link">
                            Další <i class="fas fa-chevron-right"></i>
                        </a>
                    <?php endif; ?>
                </div>
            <?php endif; ?>
        <?php endif; ?>
    </div>

    <!-- Preview Tooltip -->
    <div id="previewTooltip" class="preview-tooltip">
        <div class="preview-loading">
            <i class="fas fa-spinner fa-spin"></i> Načítám náhled...
        </div>
    </div>

    <script>
    // Preview tooltip functionality
    let previewFormat = 'text';
    let previewTimeout = null;
    let activeRequest = null;

    function loadPreviewFormat() {
        const saved = sessionStorage.getItem('previewFormat');
        if (saved) {
            previewFormat = saved;
            const checkbox = document.getElementById('htmlPreviewToggle');
            if (checkbox) {
                checkbox.checked = (previewFormat === 'html');
            }
        }
    }

    function toggleHtmlPreview(enabled) {
        previewFormat = enabled ? 'html' : 'text';
        sessionStorage.setItem('previewFormat', previewFormat);
        hidePreview();
    }

    document.addEventListener('DOMContentLoaded', function() {
        loadPreviewFormat();

        const rows = document.querySelectorAll('.message-row');
        const tooltip = document.getElementById('previewTooltip');

        rows.forEach(function(row) {
            const subjectCell = row.querySelector('.subject-field');
            if (!subjectCell) return;

            const msgId = row.id.replace('row_', '');

            subjectCell.addEventListener('mouseenter', function(e) {
                previewTimeout = setTimeout(function() {
                    showPreview(msgId, e.clientX, e.clientY);
                }, 500);
            });

            subjectCell.addEventListener('mouseleave', function() {
                clearTimeout(previewTimeout);
                hidePreview();
            });

            subjectCell.addEventListener('mousemove', function(e) {
                if (tooltip.classList.contains('active')) {
                    positionTooltip(e.clientX, e.clientY);
                }
            });
        });

        tooltip.addEventListener('mouseenter', function() {
            clearTimeout(previewTimeout);
        });

        tooltip.addEventListener('mouseleave', function() {
            hidePreview();
        });

        window.addEventListener('scroll', function() {
            if (tooltip.classList.contains('active')) {
                hidePreview();
            }
        }, { passive: true });
    });

    function showPreview(msgId, x, y) {
        const tooltip = document.getElementById('previewTooltip');

        if (activeRequest) {
            activeRequest.abort();
        }

        tooltip.innerHTML = '<div class="preview-loading"><i class="fas fa-spinner fa-spin"></i> Načítám náhled...</div>';
        tooltip.classList.add('active');
        positionTooltip(x, y);

        activeRequest = new XMLHttpRequest();
        activeRequest.open('GET', 'api_message_preview.php?id=' + encodeURIComponent(msgId) + '&format=' + previewFormat, true);

        activeRequest.onload = function() {
            if (activeRequest.status === 200) {
                try {
                    const data = JSON.parse(activeRequest.responseText);

                    if (data.success) {
                        renderPreview(data);
                    } else {
                        tooltip.innerHTML = '<div class="preview-error">Chyba: ' + escapeHtml(data.error) + '</div>';
                    }
                } catch (e) {
                    tooltip.innerHTML = '<div class="preview-error">Chyba při zpracování odpovědi</div>';
                }
            } else {
                tooltip.innerHTML = '<div class="preview-error">Nepodařilo se načíst náhled</div>';
            }
            activeRequest = null;
        };

        activeRequest.onerror = function() {
            tooltip.innerHTML = '<div class="preview-error">Chyba síťového připojení</div>';
            activeRequest = null;
        };

        activeRequest.send();
    }

    function renderPreview(data) {
        const tooltip = document.getElementById('previewTooltip');
        const contentClass = data.is_html ? 'preview-content html-mode' : 'preview-content';

        let formatIndicator = '';
        if (data.is_html) {
            formatIndicator = `<span style="font-size: 10px; color: #007bff; margin-left: 5px;">
                <i class="fas fa-code"></i> HTML režim
            </span>`;
        } else if (data.has_html) {
            formatIndicator = `<span style="font-size: 10px; color: #6c757d; margin-left: 5px;">
                <i class="fas fa-align-left"></i> Text režim
            </span>`;
        }

        tooltip.innerHTML = `
            <div class="preview-header">
                <h4><i class="fas fa-envelope"></i> Náhled zprávy ${formatIndicator}</h4>
                <div class="preview-meta"><strong>Od:</strong> ${escapeHtml(data.sender)}</div>
                <div class="preview-meta"><strong>Předmět:</strong> ${escapeHtml(data.subject)}</div>
                <div class="preview-meta"><strong>Čas:</strong> ${escapeHtml(data.timestamp)} | <strong>Skóre:</strong> ${data.score}</div>
            </div>
            <div class="${contentClass}">${data.is_html ? data.preview : escapeHtml(data.preview)}</div>
        `;
    }

    function hidePreview() {
        const tooltip = document.getElementById('previewTooltip');
        tooltip.classList.remove('active');

        if (activeRequest) {
            activeRequest.abort();
            activeRequest = null;
        }
    }

    function positionTooltip(x, y) {
        const tooltip = document.getElementById('previewTooltip');
        const offset = 15;
        const padding = 10;

        const viewportWidth = window.innerWidth;
        const viewportHeight = window.innerHeight;

        let left = x + offset;
        let top = y + offset;

        tooltip.style.opacity = '0';
        tooltip.style.display = 'block';
        const rect = tooltip.getBoundingClientRect();
        tooltip.style.opacity = '';

        if (left + rect.width > viewportWidth - padding) {
            left = x - rect.width - offset;
        }

        if (top + rect.height > viewportHeight - padding) {
            top = y - rect.height - offset;
        }

        left = Math.max(padding, Math.min(left, viewportWidth - rect.width - padding));
        top = Math.max(padding, Math.min(top, viewportHeight - rect.height - padding));

        tooltip.style.left = left + 'px';
        tooltip.style.top = top + 'px';
        tooltip.style.display = '';
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
    </script>
    <?php include 'footer.php'; ?>
</body>
</html>
