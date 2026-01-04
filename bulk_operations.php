<?php
/**
 * Bulk Operations - Mass operations on quarantined messages
 * Updated: Radio buttons, compact table, auto-learn, state colors
 */

session_start();
require_once 'config.php';
require_once 'filter_helper.php';

// Authentication check
if (!isAuthenticated()) {
    header('Location: login.php');
    exit;
}

// Permission check
$userRole = $_SESSION['user_role'] ?? 'viewer';
if (!checkPermission('domain_admin')) {
    die('Nemáte oprávnění pro hromadné operace.');
}

$db = Database::getInstance()->getConnection();
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

$pageTitle = 'Hromadné operace - Rspamd Quarantine';
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
    <link rel="stylesheet" href="css/bulk.css">
</head>
<body>
    <div class="container">
        <!-- NADPIS SE STATISTIKAMI -->
        <div class="header-with-stats">
            <div class="header-title">
                <h1><i class="fas fa-tasks"></i> Hromadné operace</h1>
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
            'reset_url' => 'bulk_operations.php?reset_filters=1',
        ]));
        ?>

        <!-- Action Legend -->
        <div class="action-legend">
            <div class="legend-item">
                <strong>Akce:</strong>
            </div>
            <div class="legend-item">
                <span class="action-spam">⬤ S</span> = Naučit SPAM
            </div>
            <div class="legend-item">
                <span class="action-ham">⬤ H</span> = Naučit HAM
            </div>
            <div class="legend-item">
                <span class="action-forget">⬤ F</span> = Zapomenout
            </div>
            <div class="legend-item">
                <span class="action-release">☑ R</span> = Uvolnit do schránky
            </div>
            <div class="legend-item" style="margin-left: auto;">
                <label style="cursor: pointer; display: flex; align-items: center; gap: 5px;">
                    <input type="checkbox" id="htmlPreviewToggle" onchange="toggleHtmlPreview(this.checked)" style="width: 16px; height: 16px; cursor: pointer;">
                    <span><i class="fas fa-code"></i> <strong>HTML náhled</strong></span>
                </label>
            </div>
        </div>

        <!-- Bulk Operations Info -->
        <div class="bulk-actions-info">
            <i class="fas fa-info-circle"></i>
            <strong>Instrukce:</strong> Pro každou zprávu vyberte jednu akci (S/H/F) a případně zaškrtněte R pro uvolnění. Poté klikněte na tlačítko "Provést operace".
        </div>

        <?php if (empty($messages)): ?>
            <div class="no-results">
                <i class="fas fa-inbox"></i>
                <h3>Žádné zprávy v karanténě</h3>
                <p>Upravte filtry nebo počkejte na nové zprávy</p>
            </div>
        <?php else: ?>
            <form method="POST" action="process_bulk.php" id="bulkForm">
                <div class="results-info">
                    Zobrazeno <strong><?php echo count($messages); ?></strong> z <strong><?php echo number_format($totalItems); ?></strong> zpráv
                    | Stránka <?php echo $page; ?> z <?php echo $totalPages; ?>
                </div>

                <table class="messages-table">
                    <thead>
                        <tr>
                            <th style="width: 110px;">Čas</th>
                            <th>Odesílatel</th>
                            <th>Příjemce</th>
                            <th>Předmět</th>
                            <th style="width: 60px;">Skóre</th>
                            <th style="width: 180px;">Akce</th>
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

                            // Unique name for radio group
                            $radioName = 'action_' . $msgId;

                            // State class for row coloring
                            $stateClass = '';
                            switch ((int)$msg['state']) {
                                case 0: $stateClass = 'state-quarantined'; break;
                                case 1: $stateClass = 'state-learned-ham'; break;
                                case 2: $stateClass = 'state-learned-spam'; break;
                                case 3: $stateClass = 'state-released'; break;
                            }

                            // Auto-learn spam detection by Rspamd
                            // Check if Rspamd already auto-learned this message
                            $autoLearnEnabled = defined('AUTOLEARN_ENABLED') ? AUTOLEARN_ENABLED : false;
                            $autoLearnScore = defined('AUTOLEARN_SCORE') ? AUTOLEARN_SCORE : 15.0;
                            $isAutoLearnSpam = false;

                            if ($autoLearnEnabled) {
                                // Check if message has auto-learn symbols from Rspamd
                                $symbols = isset($msg['symbols']) ? $msg['symbols'] : '';
                                $hasAutoLearn = (
                                    stripos($symbols, 'BAYES_SPAM') !== false ||
                                    stripos($symbols, 'NEURAL_SPAM') !== false ||
                                    ($msg['state'] == 0 && $score >= $autoLearnScore)
                                );

                                if ($hasAutoLearn) {
                                    $stateClass = 'auto-learn-spam';
                                    $isAutoLearnSpam = true;
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
                                    <?php echo htmlspecialchars(truncateText($subject, 60)); ?>
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
                                        <label class="action-label action-spam" title="Naučit SPAM">
                                            <input type="radio" name="<?php echo $radioName; ?>" value="spam" class="action-radio" onchange="updateRowState('<?php echo $msgId; ?>')" <?php echo $isAutoLearnSpam ? 'checked' : ''; ?>>
                                            <span>S</span><?php if ($isAutoLearnSpam) echo ' <i class="fas fa-robot" style="font-size:9px;" title="Auto-learn by Rspamd"></i>'; ?>
                                        </label>
                                        <label class="action-label action-ham" title="Naučit HAM">
                                            <input type="radio" name="<?php echo $radioName; ?>" value="ham" class="action-radio" onchange="updateRowState('<?php echo $msgId; ?>')">
                                            <span>H</span>
                                        </label>
                                        <label class="action-label action-forget" title="Zapomenout">
                                            <input type="radio" name="<?php echo $radioName; ?>" value="forget" class="action-radio" onchange="updateRowState('<?php echo $msgId; ?>')">
                                            <span>F</span>
                                        </label>
                                        <label class="action-label action-release" title="Uvolnit">
                                            <input type="checkbox" name="release_<?php echo $msgId; ?>" value="1" class="action-checkbox" onchange="updateRowState('<?php echo $msgId; ?>')">
                                            <span>R</span>
                                        </label>
                                    </div>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>

                <!-- Bulk Submit Button -->
                <div class="bulk-submit-container">
                    <button type="submit" class="bulk-submit-btn" id="bulkSubmitBtn" disabled>
                        <i class="fas fa-play-circle"></i> Provést operace
                        <span class="selected-count" id="selectedCount">0</span>
                    </button>
                    <div style="margin-top: 10px; color: #6c757d; font-size: 13px;">
                        <i class="fas fa-info-circle"></i> Vyberte akce před odesláním
                    </div>
                </div>

                <!-- Pagination -->
                <?php if ($totalPages > 1): ?>
                    <div class="pagination">
                        <?php if ($page > 1): ?>
                            <a href="?page=<?php echo $page - 1; ?>&<?php echo http_build_query(array_diff_key($_GET, ['page' => ''])); ?>" class="page-link">
                                <i class="fas fa-chevron-left"></i> Předchozí
                            </a>
                        <?php endif; ?>

                        <?php
                        $start = max(1, $page - 2);
                        $end = min($totalPages, $page + 2);
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
            </form>
        <?php endif; ?>
    </div>

    <script>
    // Update row visual state and count selected actions
    function updateRowState(msgId) {
        const row = document.getElementById('row_' + msgId);
        const radios = document.querySelectorAll('input[name="action_' + msgId + '"]');
        const checkbox = document.querySelector('input[name="release_' + msgId + '"]');

        // Check if any action is selected
        let hasAction = false;
        radios.forEach(function(radio) {
            if (radio.checked) hasAction = true;
        });
        if (checkbox && checkbox.checked) hasAction = true;

        // Update row visual state
        if (hasAction) {
            row.classList.add('has-action');
        } else {
            row.classList.remove('has-action');
        }

        updateSelectedCount();
    }

    // Count messages with selected actions
    function updateSelectedCount() {
        const allRadios = document.querySelectorAll('input[type="radio"]');
        const allCheckboxes = document.querySelectorAll('input[type="checkbox"][name^="release_"]');
        let count = 0;
        const processedMessages = new Set();

        // Count radio selections
        allRadios.forEach(function(radio) {
            if (radio.checked) {
                const msgId = radio.name.replace('action_', '');
                processedMessages.add(msgId);
            }
        });

        // Count checkbox selections
        allCheckboxes.forEach(function(checkbox) {
            if (checkbox.checked) {
                const msgId = checkbox.name.replace('release_', '');
                processedMessages.add(msgId);
            }
        });

        count = processedMessages.size;

        const countDisplay = document.getElementById('selectedCount');
        const submitBtn = document.getElementById('bulkSubmitBtn');

        if (countDisplay) {
            countDisplay.textContent = count;
        }

        if (submitBtn) {
            submitBtn.disabled = (count === 0);
        }
    }

    // Form validation before submit
    document.getElementById('bulkForm')?.addEventListener('submit', function(e) {
        const allRadios = document.querySelectorAll('input[type="radio"]:checked');
        const allCheckboxes = document.querySelectorAll('input[type="checkbox"][name^="release_"]:checked');

        if (allRadios.length === 0 && allCheckboxes.length === 0) {
            e.preventDefault();
            alert('Vyberte alespoň jednu akci pro zpracování.');
            return false;
        }

        // Count total operations
        const processedMessages = new Set();
        allRadios.forEach(function(radio) {
            const msgId = radio.name.replace('action_', '');
            processedMessages.add(msgId);
        });
        allCheckboxes.forEach(function(checkbox) {
            const msgId = checkbox.name.replace('release_', '');
            processedMessages.add(msgId);
        });

        const count = processedMessages.size;

        // Confirmation
        if (!confirm('Opravdu chcete provést operace na ' + count + ' zprávách?')) {
            e.preventDefault();
            return false;
        }
    });

    // Initialize on page load
    document.addEventListener('DOMContentLoaded', function() {
        // Update all rows including auto-learned ones
        const allRows = document.querySelectorAll('.message-row');
        allRows.forEach(function(row) {
            const msgId = row.id.replace('row_', '');
            updateRowState(msgId);
        });
        updateSelectedCount();
    });
    </script>

    <!-- Preview Tooltip -->
    <div id="previewTooltip" class="preview-tooltip">
        <div class="preview-loading">
            <i class="fas fa-spinner fa-spin"></i> Načítám náhled...
        </div>
    </div>

    <script>
    // Global preview format
    let previewFormat = 'text';
    let previewTimeout = null;
    let activeRequest = null;

    // Load format from sessionStorage
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

    // Toggle HTML preview
    function toggleHtmlPreview(enabled) {
        previewFormat = enabled ? 'html' : 'text';
        sessionStorage.setItem('previewFormat', previewFormat);

        hidePreview();
        setTimeout(function() {
            const hoveredRow = document.querySelector('.subject-field:hover');
            if (hoveredRow) {
                const row = hoveredRow.closest('.message-row');
                if (row) {
                    const msgId = row.id.replace('row_', '');
                    const rect = hoveredRow.getBoundingClientRect();
                    showPreview(msgId, rect.left + rect.width / 2, rect.top + rect.height / 2);
                }
            }
        }, 100);
    }

    // Initialize on load
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
