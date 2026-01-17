<?php
/**
 * Language Helper - Multilanguage Support
 * Auto-detects browser language and loads appropriate translations
 */

class Lang {
    private static $instance = null;
    private $currentLang = 'cs';
    private $translations = [];
    private $fallbackLang = 'cs';
    private $availableLangs = ['cs', 'en', 'de', 'sk'];

    private function __construct() {
        $this->detectLanguage();
        $this->loadTranslations();
    }

    public static function getInstance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    /**
     * Detect language from browser Accept-Language header
     */
    private function detectLanguage() {
        $hasManualSelection = (!empty($_SESSION['lang_manual']) || (!empty($_COOKIE['lang_manual']) && $_COOKIE['lang_manual'] === '1'));

        if ($hasManualSelection) {
            // Check if language is set in session
            if (isset($_SESSION['lang']) && in_array($_SESSION['lang'], $this->availableLangs)) {
                $this->currentLang = $_SESSION['lang'];
                return;
            }

            // Check if language is set in cookie
            if (isset($_COOKIE['lang']) && in_array($_COOKIE['lang'], $this->availableLangs)) {
                $this->currentLang = $_COOKIE['lang'];
                $_SESSION['lang'] = $this->currentLang;
                return;
            }
        }

        // Detect from browser
        if (isset($_SERVER['HTTP_ACCEPT_LANGUAGE'])) {
            $browserLangs = explode(',', $_SERVER['HTTP_ACCEPT_LANGUAGE']);

            foreach ($browserLangs as $lang) {
                // Extract language code (e.g., "cs" from "cs-CZ" or "cs")
                $langCode = strtolower(substr(trim($lang), 0, 2));

                if (in_array($langCode, $this->availableLangs)) {
                    $this->currentLang = $langCode;
                    $_SESSION['lang'] = $this->currentLang;
                    setcookie('lang', $this->currentLang, time() + (365 * 24 * 60 * 60), '/');
                    return;
                }
            }
        }

        if (!$hasManualSelection) {
            if (isset($_SESSION['lang']) && in_array($_SESSION['lang'], $this->availableLangs)) {
                $this->currentLang = $_SESSION['lang'];
                return;
            }

            if (isset($_COOKIE['lang']) && in_array($_COOKIE['lang'], $this->availableLangs)) {
                $this->currentLang = $_COOKIE['lang'];
                $_SESSION['lang'] = $this->currentLang;
                return;
            }
        }

        // Default to Czech
        $this->currentLang = $this->fallbackLang;
    }

    /**
     * Load translations for current language
     */
    private function loadTranslations() {
        $langFile = __DIR__ . '/lang/' . $this->currentLang . '.php';

        if (file_exists($langFile)) {
            $this->translations = require $langFile;
        }

        // Load fallback language if current is not Czech
        if ($this->currentLang !== $this->fallbackLang) {
            $fallbackFile = __DIR__ . '/lang/' . $this->fallbackLang . '.php';
            if (file_exists($fallbackFile)) {
                $fallback = require $fallbackFile;
                // Merge with fallback (current lang takes precedence)
                $this->translations = array_merge($fallback, $this->translations);
            }
        }
    }

    /**
     * Get translation for key
     */
    public function get($key, $params = []) {
        $translation = $this->translations[$key] ?? $key;

        // Replace parameters
        if (!empty($params)) {
            foreach ($params as $placeholder => $value) {
                $translation = str_replace('{' . $placeholder . '}', $value, $translation);
            }
        }

        return $translation;
    }

    /**
     * Get current language code
     */
    public function getCurrentLang() {
        return $this->currentLang;
    }

    /**
     * Set language manually
     */
    public function setLanguage($langCode) {
        if (in_array($langCode, $this->availableLangs)) {
            $this->currentLang = $langCode;
            $_SESSION['lang'] = $langCode;
            $_SESSION['lang_manual'] = true;
            setcookie('lang', $langCode, time() + (365 * 24 * 60 * 60), '/');
            setcookie('lang_manual', '1', time() + (365 * 24 * 60 * 60), '/');
            $this->loadTranslations();
            return true;
        }
        return false;
    }

    /**
     * Get available languages
     */
    public function getAvailableLanguages() {
        return [
            'cs' => 'Čeština',
            'en' => 'English',
            'de' => 'Deutsch',
            'sk' => 'Slovenčina'
        ];
    }
}

/**
 * Helper function for translations
 */
function __($key, $params = []) {
    return Lang::getInstance()->get($key, $params);
}

/**
 * Helper function to get current language
 */
function currentLang() {
    return Lang::getInstance()->getCurrentLang();
}
?>
