<?php
/**
 * Filter Helper Functions
 * Provides reusable filter functionality with session persistence
 */
require_once __DIR__ . '/lang_helper.php';

/**
 * Initialize filter session if not exists
 */
function initFilterSession(string $sessionKey = 'search_filters'): void {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }

    if (!isset($_SESSION[$sessionKey])) {
        $_SESSION[$sessionKey] = [];
    }

    // Handle reset
    if (isset($_GET['reset_filters']) && $_GET['reset_filters'] == '1') {
        $_SESSION[$sessionKey] = [];
        header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
        exit;
    }

    // Store GET params to session
    foreach ($_GET as $key => $value) {
        if ($key !== 'page' && $key !== 'reset_filters') {
            if ($value !== '' && $value !== null) {
                $_SESSION[$sessionKey][$key] = $value;
            } else {
                unset($_SESSION[$sessionKey][$key]);
            }
        }
    }
}

/**
 * Get single filter value from GET or SESSION
 */
function getFilterValue(string $key, string $sessionKey = 'search_filters'): string {
    if (isset($_GET[$key])) {
        return $_GET[$key];
    }
    if (isset($_SESSION[$sessionKey][$key])) {
        return $_SESSION[$sessionKey][$key];
    }
    return '';
}

/**
 * Get all filters from request (GET) or session as array
 */
function getFiltersFromRequest(string $sessionKey = 'search_filters'): array {
    initFilterSession($sessionKey);

    $filterParams = [
        'search',
        'action',
        'score_min',
        'score_max',
        'statefilter',
        'date',  // Updated: using single date filter instead of date_from/date_to.
        'sender',
        'recipient',
        'ip',
        'country',
        'auth_user',
        'virus',
        'bad_extension',
    ];

    $filters = [];
    foreach ($filterParams as $param) {
        $value = getFilterValue($param, $sessionKey);
        if ($value !== '') {
            $filters[$param] = $value;
        }
    }

    return $filters;
}

/**
 * Define search filters configuration
 */
function defineSearchFilters(array $options = [], string $sessionKey = 'search_filters'): array {
    initFilterSession($sessionKey);

    $defaults = [
        'show_search' => true,
        'show_action' => true,
        'show_score_min' => true,
        'show_score_max' => true,
        'show_date' => true,
        'show_sender' => true,
        'show_recipient' => true,
        'show_state' => true,
        'show_ip' => true,
        'show_country' => false,
        'show_auth_user' => true,
        'show_virus' => false,
        'show_bad_extension' => false,
        'columns' => 4,
        'form_id' => 'filterForm',
        'reset_url' => 'index.php?reset_filters=1',
    ];

    $opts = array_merge($defaults, $options);
    $filters = [];

    if ($opts['show_search']) {
        $filters['search'] = [
            'key' => 'search',
            'type' => 'text',
            'label' => __('search'),
            'icon' => 'fas fa-search',
            'placeholder' => __('filter_search_placeholder'),
            'value' => getFilterValue('search', $sessionKey),
            'class' => 'filter-group',
        ];
    }

    if ($opts['show_action']) {
        $filters['action'] = [
            'key' => 'action',
            'type' => 'select',
            'label' => __('filter_action'),
            'icon' => 'fas fa-flag',
            'value' => getFilterValue('action', $sessionKey),
            'class' => 'filter-group',
            'options' => [
                '' => __('filter_all_actions'),
                'reject' => __('action_reject'),
                'no action' => __('action_no_action'),
                'add header' => __('action_add_header'),
                'rewrite subject' => __('action_rewrite_subject'),
            ],
        ];
    }

    if ($opts['show_score_min']) {
        $filters['score_min'] = [
            'key' => 'score_min',
            'type' => 'number',
            'label' => __('filter_min_score'),
            'icon' => 'fas fa-chart-line',
            'step' => '0.1',
            'placeholder' => __('filter_score_min_placeholder'),
            'value' => getFilterValue('score_min', $sessionKey),
            'class' => 'filter-group score-min',
        ];
    }

    if ($opts['show_score_max']) {
        $filters['score_max'] = [
            'key' => 'score_max',
            'type' => 'number',
            'label' => __('filter_max_score'),
            'icon' => 'fas fa-chart-line',
            'step' => '0.1',
            'placeholder' => __('filter_score_max_placeholder'),
            'value' => getFilterValue('score_max', $sessionKey),
            'class' => 'filter-group score-max',
        ];
    }

    if ($opts['show_state']) {
        $filters['statefilter'] = [
            'key' => 'statefilter',
            'type' => 'select',
            'label' => __('msg_status'),
            'icon' => 'fas fa-flag',
            'value' => getFilterValue('statefilter', $sessionKey),
            'class' => 'filter-group',
            'options' => [
                '' => __('state_all'),
                '0' => __('state_quarantined'),
                '1' => __('state_learned_ham'),
                '2' => __('state_learned_spam'),
                '3' => __('state_released'),
            ],
        ];
    }

    if ($opts['show_date']) {
        $filters['date'] = [
            'key' => 'date',
            'type' => 'date',
            'label' => __('date'),
            'icon' => 'fas fa-calendar',
            'value' => getFilterValue('date', $sessionKey),
            'class' => 'filter-group date-filter',
        ];
    }

    if ($opts['show_sender']) {
        $filters['sender'] = [
            'key' => 'sender',
            'type' => 'text',
            'label' => __('msg_sender'),
            'icon' => 'fas fa-paper-plane',
            'placeholder' => __('filter_sender_placeholder'),
            'value' => getFilterValue('sender', $sessionKey),
            'class' => 'filter-group',
        ];
    }

    if ($opts['show_recipient']) {
        $filters['recipient'] = [
            'key' => 'recipient',
            'type' => 'text',
            'label' => __('msg_recipient'),
            'icon' => 'fas fa-inbox',
            'placeholder' => __('filter_recipient_placeholder'),
            'value' => getFilterValue('recipient', $sessionKey),
            'class' => 'filter-group',
        ];
    }

    if ($opts['show_ip']) {
        $filters['ip'] = [
            'key' => 'ip',
            'type' => 'text',
            'label' => __('filter_ip'),
            'icon' => 'fas fa-network-wired',
            'placeholder' => __('filter_ip_placeholder'),
            'value' => getFilterValue('ip', $sessionKey),
            'class' => 'filter-group',
        ];
    }

    if ($opts['show_country']) {
        $filters['country'] = [
            'key' => 'country',
            'type' => 'text',
            'label' => __('filter_country'),
            'icon' => 'fas fa-flag',
            'placeholder' => __('filter_country_placeholder'),
            'value' => getFilterValue('country', $sessionKey),
            'class' => 'filter-group',
        ];
    }

    if ($opts['show_auth_user']) {
        $filters['auth_user'] = [
            'key' => 'auth_user',
            'type' => 'text',
            'label' => __('filter_auth_user'),
            'icon' => 'fas fa-user',
            'placeholder' => __('filter_auth_user_placeholder'),
            'value' => getFilterValue('auth_user', $sessionKey),
            'class' => 'filter-group',
        ];
    }

    if ($opts['show_virus']) {
        $filters['virus'] = [
            'key' => 'virus',
            'type' => 'checkbox',
            'label' => __('filter_virus'),
            'icon' => 'fas fa-virus',
            'value' => getFilterValue('virus', $sessionKey),
            'class' => 'filter-group',
        ];
    }

    if ($opts['show_bad_extension']) {
        $filters['bad_extension'] = [
            'key' => 'bad_extension',
            'type' => 'checkbox',
            'label' => __('filter_bad_extension'),
            'icon' => 'fas fa-file-circle-xmark',
            'value' => getFilterValue('bad_extension', $sessionKey),
            'class' => 'filter-group',
        ];
    }

    $filters['_meta'] = [
        'columns' => $opts['columns'],
        'form_id' => $opts['form_id'],
        'reset_url' => $opts['reset_url'],
    ];

    return $filters;
}

function getQuarantineFilters(array $options = []): array {
    return defineSearchFilters($options);
}

function renderSearchFilters(array $filters_def): string {
    $meta = $filters_def['_meta'] ?? [];
    $formId = $meta['form_id'] ?? 'filterForm';
    unset($filters_def['_meta']);

    ob_start();
    ?>

    <style>
    .compact-filter-form {
        background: #ddd;
        padding: 12px;
        border-radius: 6px;
        margin-bottom: 15px;
    }

    .compact-filter-row {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
        align-items: flex-end;
    }

    .compact-filter-item {
        flex: 1 1 auto;
        min-width: 150px;
        max-width: 250px;
        position: relative;
    }

    .compact-filter-item label {
        display: block;
        font-size: 11px;
        font-weight: 600;
        color: #495057;
        margin-bottom: 3px;
        text-transform: uppercase;
        letter-spacing: 0.3px;
    }

    .compact-filter-item label i {
        margin-right: 4px;
        font-size: 10px;
        opacity: 0.7;
    }

    .filter-input-wrapper {
        position: relative;
        display: flex;
        align-items: center;
    }

    .compact-filter-item input,
    .compact-filter-item select {
        width: 100%;
        padding: 6px 8px;
        border: 1px solid #ced4da;
        border-radius: 4px;
        font-size: 13px;
        transition: border-color 0.15s, box-shadow 0.15s, background-color 0.15s;
    }

    .compact-filter-item input.has-value,
    .compact-filter-item select.has-value {
        border: 2px solid #007bff !important;
        background-color: #e7f3ff;
        box-shadow: 0 0 0 2px rgba(0, 123, 255, 0.15);
        padding: 5px 28px 5px 7px;
    }

    .compact-filter-item input:focus,
    .compact-filter-item select:focus {
        outline: none;
        border-color: #007bff;
        box-shadow: 0 0 0 2px rgba(0, 123, 255, 0.15);
    }

    .filter-clear-btn {
        position: absolute;
        right: 6px;
        top: 50%;
        transform: translateY(-50%);
        background: #dc3545;
        color: white;
        border: none;
        border-radius: 50%;
        width: 18px;
        height: 18px;
        font-size: 11px;
        line-height: 1;
        cursor: pointer;
        display: none;
        padding: 0;
        align-items: center;
        justify-content: center;
        transition: background 0.2s;
        z-index: 10;
    }

    .filter-clear-btn:hover {
        background: #c82333;
    }

    .compact-filter-item.has-value .filter-clear-btn {
        display: flex;
    }

    .compact-filter-submit {
        flex: 0 0 auto;
        padding: 6px 16px;
        background: #007bff;
        color: white;
        border: none;
        border-radius: 4px;
        font-size: 13px;
        font-weight: 600;
        cursor: pointer;
        transition: background 0.2s;
        height: 32px;
        margin-bottom: 0;
        align-self: flex-end;
    }

    .compact-filter-submit:hover {
        background: #0056b3;
    }

    .compact-filter-submit i {
        margin-right: 5px;
    }

    @media (max-width: 768px) {
        .compact-filter-item {
            min-width: 120px;
        }
        .compact-filter-submit {
            width: 100%;
            margin-top: 8px;
        }
    }
    </style>

    <form method="GET" id="<?php echo htmlspecialchars($formId); ?>" class="compact-filter-form">
        <div class="compact-filter-row">
            <?php foreach ($filters_def as $filter): ?>
                <?php $isChecked = ($filter['type'] === 'checkbox' && !empty($filter['value'])); ?>
                <div class="compact-filter-item <?php echo (!empty($filter['value']) && $filter['value'] !== '') ? 'has-value' : ''; ?>">
                    <label for="<?php echo htmlspecialchars($filter['key']); ?>">
                        <?php if (!empty($filter['icon'])): ?>
                            <i class="<?php echo htmlspecialchars($filter['icon']); ?>"></i>
                        <?php endif; ?>
                        <?php echo htmlspecialchars($filter['label']); ?>
                    </label>

                    <div class="filter-input-wrapper">
                        <?php if ($filter['type'] === 'select'): ?>
                            <select 
                                name="<?php echo htmlspecialchars($filter['key']); ?>" 
                                id="<?php echo htmlspecialchars($filter['key']); ?>"
                                class="<?php echo (!empty($filter['value']) && $filter['value'] !== '') ? 'has-value' : ''; ?>"
                                onchange="this.form.submit()">
                                <?php foreach ($filter['options'] as $val => $label): ?>
                                    <option value="<?php echo htmlspecialchars($val); ?>"
                                        <?php echo ($filter['value'] == $val) ? 'selected' : ''; ?>>
                                        <?php echo htmlspecialchars($label); ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        <?php elseif ($filter['type'] === 'checkbox'): ?>
                            <input type="hidden" name="<?php echo htmlspecialchars($filter['key']); ?>" value="">
                            <input
                                type="checkbox"
                                name="<?php echo htmlspecialchars($filter['key']); ?>"
                                id="<?php echo htmlspecialchars($filter['key']); ?>"
                                value="1"
                                class="<?php echo $isChecked ? 'has-value' : ''; ?>"
                                <?php echo $isChecked ? 'checked' : ''; ?>
                                onchange="this.form.submit()">
                        <?php else: ?>
                            <input 
                                type="<?php echo htmlspecialchars($filter['type']); ?>"
                                name="<?php echo htmlspecialchars($filter['key']); ?>"
                                id="<?php echo htmlspecialchars($filter['key']); ?>"
                                value="<?php echo htmlspecialchars($filter['value']); ?>"
                                class="<?php echo (!empty($filter['value']) && $filter['value'] !== '') ? 'has-value' : ''; ?>"
                                placeholder="<?php echo htmlspecialchars($filter['placeholder'] ?? ''); ?>"
                                <?php if (isset($filter['step'])): ?>
                                    step="<?php echo htmlspecialchars($filter['step']); ?>"
                                <?php endif; ?>
                                onchange="this.form.submit()">
                        <?php endif; ?>

                        <button type="button" class="filter-clear-btn" 
                                onclick="clearFilterField('<?php echo htmlspecialchars($filter['key']); ?>')"
                                title="<?php echo htmlspecialchars(__('filter_clear')); ?>">
                            ×
                        </button>
                    </div>
                </div>
            <?php endforeach; ?>

            <button type="submit" class="compact-filter-submit">
                <i class="fas fa-search"></i> <?php echo htmlspecialchars(__('search')); ?>
            </button>
        </div>
    </form>

    <script>
    function clearFilterField(fieldName) {
        const form = document.getElementById('<?php echo htmlspecialchars($formId); ?>');
        if (!form) return;

        const field = form.querySelector('[name="' + fieldName + '"]:not([type="hidden"])');
        if (!field) return;

        if (field.tagName === 'SELECT') {
            field.selectedIndex = 0;
        } else if (field.type === 'checkbox') {
            field.checked = false;
        } else {
            field.value = '';
        }

        form.submit();
    }

    document.addEventListener('DOMContentLoaded', function() {
        const form = document.getElementById('<?php echo htmlspecialchars($formId); ?>');
        if (!form) return;

        function markActiveFields() {
            form.querySelectorAll('.compact-filter-item').forEach(function(item) {
                const input = item.querySelector('input:not([type="hidden"]), select');
                if (!input) return;

                const hasValue = (input.type === 'checkbox')
                    ? input.checked
                    : (input.value && input.value.trim() !== '');

                if (hasValue) {
                    item.classList.add('has-value');
                    input.classList.add('has-value');
                } else {
                    item.classList.remove('has-value');
                    input.classList.remove('has-value');
                }
            });
        }

        markActiveFields();

        form.addEventListener('change', function(e) {
            markActiveFields();
        });

        form.addEventListener('input', function(e) {
            markActiveFields();
        });
    });
    </script>

    <?php
    return ob_get_clean();
}

function renderCompactFilters(array $filters_def): string {
    return renderSearchFilters($filters_def);
}

function clearFilters(string $sessionKey = 'search_filters'): void {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    $_SESSION[$sessionKey] = [];
}

function hasActiveFilters(string $sessionKey = 'search_filters'): bool {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    return !empty($_SESSION[$sessionKey]);
}

function countActiveFilters(string $sessionKey = 'search_filters'): int {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    return count($_SESSION[$sessionKey] ?? []);
}


/**
 * Build query string from filters array
 * Useful for creating pagination and filter links
 * 
 * @param array $params Associative array of parameters
 * @return string URL-encoded query string
 */
function buildQueryString($params = []) {
    // Remove empty values and null
    $filtered = array_filter($params, function($value) {
        return $value !== '' && $value !== null;
    });

    if (empty($filtered)) {
        return '';
    }

    return http_build_query($filtered);
}

/**
 * Render pagination controls.
 *
 * @param int   $page        Current page.
 * @param int   $totalPages  Total number of pages.
 * @param array $queryParams Base query parameters (without page).
 * @param array $options     Rendering options.
 * @return string HTML for pagination.
 */
function renderPagination(int $page, int $totalPages, array $queryParams = [], array $options = []): string {
    if ($totalPages <= 1) {
        return '';
    }

    $defaults = [
        'max_buttons' => 7,
        'show_first_last' => false,
        'show_prev_next' => true,
        'link_class' => '',
        'active_class' => 'active',
        'first_label' => '&laquo;',
        'prev_label' => '&lsaquo;',
        'next_label' => '&rsaquo;',
        'last_label' => '&raquo;',
        'title_first' => null,
        'title_prev' => null,
        'title_next' => null,
        'title_last' => null,
    ];

    $opts = array_merge($defaults, $options);
    $maxButtons = max(1, (int)$opts['max_buttons']);
    $startPage = max(1, $page - floor($maxButtons / 2));
    $endPage = min($totalPages, $startPage + $maxButtons - 1);
    $startPage = max(1, $endPage - $maxButtons + 1);

    $linkClass = trim((string)$opts['link_class']);

    $buildLink = function (int $targetPage) use ($queryParams): string {
        return '?' . buildQueryString(array_merge($queryParams, ['page' => $targetPage]));
    };

    $renderLink = function (string $href, string $label, bool $isActive = false, ?string $title = null) use ($linkClass, $opts): void {
        $classes = [];
        if ($linkClass !== '') {
            $classes[] = $linkClass;
        }
        if ($isActive && $opts['active_class'] !== '') {
            $classes[] = $opts['active_class'];
        }
        $classAttr = $classes ? ' class="' . htmlspecialchars(implode(' ', $classes)) . '"' : '';
        $titleAttr = $title ? ' title="' . htmlspecialchars($title) . '"' : '';
        echo '<a href="' . $href . '"' . $classAttr . $titleAttr . '>' . $label . '</a>';
    };

    ob_start();
    ?>
    <div class="pagination">
        <?php if ($opts['show_first_last'] && $page > 1): ?>
            <?php $renderLink($buildLink(1), $opts['first_label'], false, $opts['title_first']); ?>
        <?php endif; ?>

        <?php if ($opts['show_prev_next'] && $page > 1): ?>
            <?php $renderLink($buildLink($page - 1), $opts['prev_label'], false, $opts['title_prev']); ?>
        <?php endif; ?>

        <?php for ($i = $startPage; $i <= $endPage; $i++): ?>
            <?php $renderLink($buildLink($i), (string)$i, $i === $page); ?>
        <?php endfor; ?>

        <?php if ($opts['show_prev_next'] && $page < $totalPages): ?>
            <?php $renderLink($buildLink($page + 1), $opts['next_label'], false, $opts['title_next']); ?>
        <?php endif; ?>

        <?php if ($opts['show_first_last'] && $page < $totalPages): ?>
            <?php $renderLink($buildLink($totalPages), $opts['last_label'], false, $opts['title_last']); ?>
        <?php endif; ?>
    </div>
    <?php

    return ob_get_clean();
}

/**
 * Render stats cards for trace page
 * 
 * @param array $stats Statistics data
 * @return string HTML for stats cards
 */
function renderTraceStatsCards($stats) {
    ob_start();

    $stats = array_merge([
        'total' => 0,
        'rejected' => 0,
        'passed' => 0,
        'marked' => 0,
        'greylisted' => 0,
        'avg_score' => 0,
        'max_score' => 0,
    ], $stats);

    $rejectPct = $stats['total'] > 0 ? ($stats['rejected'] / $stats['total'] * 100) : 0;
    $passPct = $stats['total'] > 0 ? ($stats['passed'] / $stats['total'] * 100) : 0;
    $markPct = $stats['total'] > 0 ? ($stats['marked'] / $stats['total'] * 100) : 0;
    ?>
    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-icon">
                <i class="fas fa-envelope"></i>
            </div>
            <div class="stat-content">
                <div class="stat-label">Celkem zpráv</div>
                <div class="stat-value"><?php echo number_format($stats['total']); ?></div>
            </div>
        </div>

        <div class="stat-card stat-danger">
            <div class="stat-icon">
                <i class="fas fa-ban"></i>
            </div>
            <div class="stat-content">
                <div class="stat-label">Zamítnuto</div>
                <div class="stat-value"><?php echo number_format($stats['rejected']); ?></div>
                <div class="stat-percentage"><?php echo number_format($rejectPct, 1); ?>%</div>
            </div>
        </div>

        <div class="stat-card stat-success">
            <div class="stat-icon">
                <i class="fas fa-check-circle"></i>
            </div>
            <div class="stat-content">
                <div class="stat-label">Propuštěno</div>
                <div class="stat-value"><?php echo number_format($stats['passed']); ?></div>
                <div class="stat-percentage"><?php echo number_format($passPct, 1); ?>%</div>
            </div>
        </div>

        <div class="stat-card stat-warning">
            <div class="stat-icon">
                <i class="fas fa-tag"></i>
            </div>
            <div class="stat-content">
                <div class="stat-label">Označeno</div>
                <div class="stat-value"><?php echo number_format($stats['marked']); ?></div>
                <div class="stat-percentage"><?php echo number_format($markPct, 1); ?>%</div>
            </div>
        </div>

        <div class="stat-card stat-info">
            <div class="stat-icon">
                <i class="fas fa-chart-line"></i>
            </div>
            <div class="stat-content">
                <div class="stat-label">Průměrné skóre</div>
                <div class="stat-value"><?php echo number_format($stats['avg_score'], 2); ?></div>
                <div class="stat-percentage">max: <?php echo number_format($stats['max_score'], 2); ?></div>
            </div>
        </div>
    </div>
    <?php
    return ob_get_clean();
}

/**
 * Render action pills for trace page
 * 
 * @param array $stats Statistics data
 * @param array $filters Current filters
 * @return string HTML for action pills
 */
function renderTraceActionPills($stats, $filters) {
    ob_start();

    $stats = array_merge([
        'total' => 0,
        'rejected' => 0,
        'passed' => 0,
        'marked' => 0,
        'greylisted' => 0,
    ], $stats);
    ?>
    <div class="filter-pills">
        <a href="?<?php echo buildQueryString(array_merge($filters, ['action' => null, 'page' => null])); ?>" 
           class="pill <?php echo empty($filters['action']) ? 'active' : ''; ?>">
            <i class="fas fa-globe"></i> Vše
            <span class="pill-count"><?php echo number_format($stats['total']); ?></span>
        </a>
        <a href="?<?php echo buildQueryString(array_merge($filters, ['action' => 'reject', 'page' => null])); ?>" 
           class="pill pill-danger <?php echo ($filters['action'] ?? '') === 'reject' ? 'active' : ''; ?>">
            <i class="fas fa-ban"></i> Zamítnuto
            <span class="pill-count"><?php echo number_format($stats['rejected']); ?></span>
        </a>
        <a href="?<?php echo buildQueryString(array_merge($filters, ['action' => 'no action', 'page' => null])); ?>" 
           class="pill pill-success <?php echo ($filters['action'] ?? '') === 'no action' ? 'active' : ''; ?>">
            <i class="fas fa-check-circle"></i> Propuštěno
            <span class="pill-count"><?php echo number_format($stats['passed']); ?></span>
        </a>
        <a href="?<?php echo buildQueryString(array_merge($filters, ['action' => 'add header', 'page' => null])); ?>" 
           class="pill pill-warning <?php echo ($filters['action'] ?? '') === 'add header' ? 'active' : ''; ?>">
            <i class="fas fa-tag"></i> Označeno
            <span class="pill-count"><?php echo number_format($stats['marked']); ?></span>
        </a>
        <a href="?<?php echo buildQueryString(array_merge($filters, ['action' => 'greylist', 'page' => null])); ?>" 
           class="pill pill-info <?php echo ($filters['action'] ?? '') === 'greylist' ? 'active' : ''; ?>">
            <i class="fas fa-clock"></i> Greylist
            <span class="pill-count"><?php echo number_format($stats['greylisted']); ?></span>
        </a>
    </div>
    <?php
    return ob_get_clean();
}

/**
 * Render trace filters section
 * 
 * @param array $filters Current filters
 * @return string HTML for filter section
 */

/**
 * Define audit filters configuration
 */
function defineAuditFilters(array $options = [], string $sessionKey = 'audit_filters'): array {
    initFilterSession($sessionKey);

    $defaults = [
        'show_search' => true,
        'show_action' => true,
        'show_username' => true,
        'show_date_from' => true,
        'show_date_to' => true,
        'columns' => 4,
        'form_id' => 'auditFilterForm',
        'reset_url' => 'audit.php?reset_filters=1',
    ];

    $opts = array_merge($defaults, $options);
    $filters = [];

    if ($opts['show_search']) {
        $filters['search'] = [
            'key' => 'search',
            'type' => 'text',
            'label' => 'Hledat',
            'icon' => 'fas fa-search',
            'placeholder' => 'Uživatel, akce, IP, detail...',
            'value' => getFilterValue('search', $sessionKey),
            'class' => 'filter-group',
        ];
    }

    if ($opts['show_action']) {
        $filters['action'] = [
            'key' => 'action',
            'type' => 'select',
            'label' => 'Akce',
            'icon' => 'fas fa-bolt',
            'value' => getFilterValue('action', $sessionKey),
            'class' => 'filter-group',
            'options' => [
                '' => 'Všechny akce',
                'release_message' => 'Uvolnění zprávy',
                'learn_spam' => 'Naučit SPAM',
                'learn_ham' => 'Naučit HAM',
                'delete_message' => 'Smazání zprávy',
                'user_updated' => 'Úprava systémového uživatele',
                'mailbox_updated' => 'Úprava doménového uživatele',
                'alias_updated' => 'Úprava doménového aliasu',
                'login_success' => 'Úspěšné přihlášení',
                'login_failed' => 'Neúspěšné přihlášení',
            ],
        ];
    }

    if ($opts['show_username']) {
        $filters['username'] = [
            'key' => 'username',
            'type' => 'text',
            'label' => 'Uživatel',
            'icon' => 'fas fa-user',
            'placeholder' => 'Uživatelské jméno',
            'value' => getFilterValue('username', $sessionKey),
            'class' => 'filter-group',
        ];
    }

    if ($opts['show_date_from']) {
        $filters['date_from'] = [
            'key' => 'date_from',
            'type' => 'date',
            'label' => 'Datum od',
            'icon' => 'far fa-calendar-alt',
            'value' => getFilterValue('date_from', $sessionKey),
            'class' => 'filter-group',
        ];
    }

    if ($opts['show_date_to']) {
        $filters['date_to'] = [
            'key' => 'date_to',
            'type' => 'date',
            'label' => 'Datum do',
            'icon' => 'far fa-calendar-alt',
            'value' => getFilterValue('date_to', $sessionKey),
            'class' => 'filter-group',
        ];
    }

    $filters['_meta'] = [
        'columns' => $opts['columns'],
        'form_id' => $opts['form_id'],
        'reset_url' => $opts['reset_url'],
    ];

    return $filters;
}

/**
 * Render audit filters using the same style as renderSearchFilters
 * @param array $filters Current filters
 * @return string HTML for filter section
 */
function renderAuditFilters($filters = []): string {
    // Prepare filter definition
    $filters_def = defineAuditFilters([
        'show_search' => true,
        'show_action' => true,
        'show_username' => true,
        'show_date_from' => true,
        'show_date_to' => true,
        'form_id' => 'auditFilterForm',
        'reset_url' => 'audit.php',
    ], 'audit_filters');

    // Use the same rendering as renderSearchFilters
    return renderSearchFilters($filters_def);
}

/**
 * Get audit filters from request
 */
function getAuditFiltersFromRequest(string $sessionKey = 'audit_filters'): array {
    initFilterSession($sessionKey);

    $filterParams = [
        'search',
        'action',
        'username',
        'date_from',
        'date_to',
    ];

    $filters = [];
    foreach ($filterParams as $param) {
        $value = getFilterValue($param, $sessionKey);
        if ($value !== '') {
            $filters[$param] = $value;
        }
    }

    return $filters;
}


function renderTraceFilters($filters) {
    ob_start();

    $filters = array_merge([
        'search' => '',
        'sender' => '',
        'recipient' => '',
        'ip' => '',
        'auth_user' => '',
        'hostname' => '',
        'date_from' => '',
        'date_to' => '',
        'score_min' => '',
        'score_max' => '',
    ], $filters);
    ?>
    <div class="filter-section">
        <div class="filter-header" onclick="toggleFilters()">
            <h3><i class="fas fa-filter"></i> Filtry a vyhledávání</h3>
            <i class="fas fa-chevron-down toggle-icon"></i>
        </div>
        <div class="filter-content" id="filterContent">
            <form method="get" action="" class="filter-form">
                <div class="filter-row">
                    <div class="filter-group">
                        <label><i class="fas fa-search"></i> Vyhledávání</label>
                        <input type="text" name="search" 
                               placeholder="Odesílatel, příjemce, předmět, Message-ID, IP..." 
                               value="<?php echo htmlspecialchars($filters['search']); ?>">
                    </div>

                    <div class="filter-group">
                        <label><i class="fas fa-paper-plane"></i> Odesílatel</label>
                        <input type="text" name="sender" 
                               placeholder="user@domain.com" 
                               value="<?php echo htmlspecialchars($filters['sender']); ?>">
                    </div>

                    <div class="filter-group">
                        <label><i class="fas fa-inbox"></i> Příjemce</label>
                        <input type="text" name="recipient" 
                               placeholder="user@domain.com" 
                               value="<?php echo htmlspecialchars($filters['recipient']); ?>">
                    </div>
                </div>

                <div class="filter-row">
                    <div class="filter-group">
                        <label><i class="fas fa-network-wired"></i> IP adresa</label>
                        <input type="text" name="ip" 
                               placeholder="192.168.1.1" 
                               value="<?php echo htmlspecialchars($filters['ip']); ?>">
                    </div>

                    <div class="filter-group">
                        <label><i class="fas fa-user"></i> Auth. uživatel</label>
                        <input type="text" name="auth_user" 
                               placeholder="username" 
                               value="<?php echo htmlspecialchars($filters['auth_user']); ?>">
                    </div>

                    <div class="filter-group">
                        <label><i class="fas fa-server"></i> Hostname</label>
                        <input type="text" name="hostname" 
                               placeholder="mail.example.com" 
                               value="<?php echo htmlspecialchars($filters['hostname']); ?>">
                    </div>
                </div>

                <div class="filter-row">
                    <div class="filter-group">
                        <label><i class="fas fa-calendar-alt"></i> Datum od</label>
                        <input type="date" name="date_from" 
                               value="<?php echo htmlspecialchars($filters['date_from']); ?>">
                    </div>

                    <div class="filter-group">
                        <label><i class="fas fa-calendar-alt"></i> Datum do</label>
                        <input type="date" name="date_to" 
                               value="<?php echo htmlspecialchars($filters['date_to']); ?>">
                    </div>

                    <div class="filter-group">
                        <label><i class="fas fa-tachometer-alt"></i> Skóre min</label>
                        <input type="number" name="score_min" step="0.1" 
                               placeholder="0.0" 
                               value="<?php echo htmlspecialchars($filters['score_min']); ?>">
                    </div>

                    <div class="filter-group">
                        <label><i class="fas fa-tachometer-alt"></i> Skóre max</label>
                        <input type="number" name="score_max" step="0.1" 
                               placeholder="100.0" 
                               value="<?php echo htmlspecialchars($filters['score_max']); ?>">
                    </div>
                </div>

                <div class="filter-actions">
                    <button type="submit" class="btn btn-primary">
                        <i class="fas fa-search"></i> Filtrovat
                    </button>
                    <a href="?" class="btn btn-secondary">
                        <i class="fas fa-times"></i> Zrušit filtry
                    </a>
                </div>
            </form>
        </div>
    </div>
    <?php
    return ob_get_clean();
}

/**
 * Get filters from request for trace page
 * 
 * @return array Filters array
 */
function getTraceFiltersFromRequest(string $sessionKey = 'search_filters') {
    initFilterSession($sessionKey);
    
      $filterParams = [
        'search',
        'action',
        'score_min',
        'score_max',
        'date',  
        'sender',
        'recipient',
        'ip',
        'country',
        'auth_user'
    ];

    $filters = [];
    foreach ($filterParams as $param) {
        $value = getFilterValue($param, $sessionKey);
        if ($value !== '') {
            $filters[$param] = $value;
        }
    }

    return $filters;
}
