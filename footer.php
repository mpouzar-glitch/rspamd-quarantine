<?php
/**
 * Rspamd Quarantine - Footer (Full Width)
 * Version 2.1.1
 */
?>
<footer class="app-footer">
    <div class="footer-content">
        <div class="footer-left">
            <span class="version-info">
                Rspamd Quarantine v<?php echo defined('QUARANTINE_VERSION') ? QUARANTINE_VERSION : '2.1.1'; ?> 
                &bull; <?php echo date('Y'); ?> 
            </span>
        </div>
        <div class="footer-right">
            <div class="footer-links">
                <?php if (isset($_SESSION['userrole']) && $_SESSION['userrole'] === 'admin'): ?>
                    <a href="stats.php" class="footer-link"><i class="fas fa-chart-bar"></i> Statistiky</a>
                    <a href="trace.php" class="footer-link"><i class="fas fa-search"></i> Trace</a>
                <?php endif; ?>
            </div>
            <div class="system-info">
                <small>PHP <?php echo PHP_VERSION; ?></small>
            </div>
        </div>
    </div>
</footer>

<style>
/* Full Width Footer - BEZ MEZER */
.app-footer {
    background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
    color: #ecf0f1;
    margin-top: 40px;
    padding: 20px 0;
    font-size: 13px;
    width: 100vw;              /* 100% viewport width */
    position: relative;
    left: 50%;
    right: 50%;
    margin-left: -50vw;
    margin-right: -50vw;
    box-sizing: border-box;
}

.footer-content {
    display: flex;
    justify-content: space-between;
    align-items: center;
    max-width: 1400px;         /* stejná jako .container */
    margin: 0 auto;
    padding: 0 20px;           /* jen boční padding jako container */
    width: 100%;
}

.footer-left {
    font-weight: 500;
}

.version-info a {
    color: #3498db;
    text-decoration: none;
}

.version-info a:hover {
    text-decoration: underline;
}

.footer-right {
    display: flex;
    align-items: center;
    gap: 20px;
}

.footer-links {
    display: flex;
    gap: 15px;
    flex-wrap: nowrap;
}

.footer-link {
    color: #bdc3c7;
    text-decoration: none;
    display: flex;
    align-items: center;
    gap: 5px;
    padding: 8px 14px;
    border-radius: 6px;
    transition: all 0.2s ease;
    white-space: nowrap;
}

.footer-link:hover {
    background: rgba(255,255,255,0.15);
    color: #ffffff;
    transform: translateY(-1px);
}

.logout {
    color: #e74c3c !important;
    border: 1px solid rgba(231,76,60,0.3);
}

.logout:hover {
    background: rgba(231,76,60,0.2) !important;
    border-color: rgba(231,76,60,0.5) !important;
    color: #ff6b6b !important;
}

.system-info {
    color: #95a5a6;
    padding-left: 20px;
    border-left: 1px solid rgba(236,240,241,0.3);
    white-space: nowrap;
}

@media (max-width: 992px) {
    .footer-content {
        flex-direction: column;
        gap: 15px;
        padding: 0 15px;
    }
    
    .footer-right {
        width: 100%;
        justify-content: center;
        gap: 10px;
    }
    
    .footer-links {
        flex-wrap: wrap;
        justify-content: center;
        gap: 10px;
    }
    
    .footer-link {
        padding: 6px 12px;
        font-size: 12px;
    }
    
    .system-info {
        border-left: none;
        padding-left: 0;
        order: -1;
        width: 100%;
        text-align: center;
    }
}

@media (max-width: 480px) {
    .app-footer {
        padding: 15px 0;
    }
    
    .footer-link {
        padding: 8px 10px;
        font-size: 11px;
    }
    
    .footer-links {
        flex-direction: column;
        gap: 5px;
    }
}
</style>
