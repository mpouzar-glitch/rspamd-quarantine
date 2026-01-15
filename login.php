<?php
/**
 * Rspamd Quarantine - Login Page
 * Version: 2.0.3
 * Fixed: Load user_domains as an array
 */

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/lang_helper.php';

$error_message = '';
$success_message = '';

function isEmailUsername(string $username): bool {
    return filter_var($username, FILTER_VALIDATE_EMAIL) !== false;
}

function isImapAuthEnabled(): bool {
    return defined('IMAP_AUTH_ENABLED') && IMAP_AUTH_ENABLED === true;
}

function attemptImapLogin(string $email, string $password): bool {
    if (!function_exists('imap_open')) {
        error_log('IMAP login failed: PHP IMAP extension is not available.');
        return false;
    }

    if (!defined('IMAP_SERVER') || IMAP_SERVER === '') {
        error_log('IMAP login failed: IMAP_SERVER is not configured.');
        return false;
    }

    $port = defined('IMAP_PORT') ? (int) IMAP_PORT : 993;
    $security = defined('IMAP_SECURITY') ? strtolower((string) IMAP_SECURITY) : 'ssl';
    $flags = '/imap';
    if (in_array($security, ['ssl', 'tls'], true)) {
        $flags .= '/' . $security;
    }
    if (defined('IMAP_VALIDATE_CERT') && IMAP_VALIDATE_CERT === false) {
        $flags .= '/novalidate-cert';
    }

    $mailbox = sprintf('{%s:%d%s}INBOX', IMAP_SERVER, $port, $flags);

    $imapStream = @imap_open($mailbox, $email, $password, 0, 1);
    if ($imapStream === false) {
        $lastError = imap_last_error();
        if ($lastError) {
            error_log('IMAP login failed: ' . $lastError);
        }
        return false;
    }

    imap_close($imapStream);
    return true;
}

// Handle logout
if (isset($_GET['logout'])) {
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
    session_unset();
    session_destroy();
    session_start();
    $success_message = __('logout_success');
}

// Handle session timeout
if (isset($_GET['timeout'])) {
    $error_message = __('login_timeout');
}

// Redirect if already authenticated
if (isAuthenticated()) {
    header('Location: index.php');
    exit;
}

// Handle login form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {

    // Validate input
    if (empty($_POST['username']) || empty($_POST['password'])) {
        $error_message = __('login_missing_credentials');
    } else {
        $username = trim($_POST['username']);
        $password = $_POST['password'];

        try {
            $db = Database::getInstance()->getConnection();

            // Get user from database
            $stmt = $db->prepare("
                SELECT id, username, password_hash, email, role, active 
                FROM users 
                WHERE username = ? AND active = 1
            ");
            $stmt->execute([$username]);
            $user = $stmt->fetch();

            if ($user && password_verify($password, $user['password_hash'])) {
                // Successful login
                $_SESSION['authenticated'] = true;
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];
                $_SESSION['user_email'] = $user['email'];
                $_SESSION['user_role'] = $user['role'];
                $_SESSION['last_activity'] = time();

                // Load user domains if domain_admin
                if ($user['role'] === 'domain_admin') {
                    $stmt = $db->prepare("
                        SELECT domain 
                        FROM user_domains 
                        WHERE user_id = ?
                        ORDER BY domain
                    ");
                    $stmt->execute([$user['id']]);

                    // Fixed: Load as array and trim each domain
                    $domains = $stmt->fetchAll(PDO::FETCH_COLUMN);
                    $_SESSION['user_domains'] = array_map('trim', $domains);

                    // Debug log
                    error_log("User {$user['username']} logged in with domains: " . implode(', ', $_SESSION['user_domains']));
                } else {
                    $_SESSION['user_domains'] = [];
                }

                // Update last login
                $stmt = $db->prepare("UPDATE users SET last_login = NOW() WHERE id = ?");
                $stmt->execute([$user['id']]);

                // Log successful login
                logAudit(
                    $user['id'], 
                    $user['username'], 
                    'login_success', 
                    'session', 
                    $user['id'], 
                    'User logged in successfully'
                );

                // Redirect to index
                header('Location: index.php');
                exit;

            } elseif (!$user && isEmailUsername($username) && isImapAuthEnabled()) {
                if (attemptImapLogin($username, $password)) {
                    $_SESSION['authenticated'] = true;
                    $_SESSION['user_id'] = null;
                    $_SESSION['username'] = $username;
                    $_SESSION['user_email'] = $username;
                    $_SESSION['user_role'] = 'quarantine_user';
                    $_SESSION['user_domains'] = [];
                    $_SESSION['last_activity'] = time();

                    logAudit(
                        null,
                        $username,
                        'login_success',
                        'session',
                        null,
                        'User logged in successfully via IMAP'
                    );

                    header('Location: index.php');
                    exit;
                }

                $error_message = __('login_failed');

                logAudit(
                    null,
                    $username,
                    'login_failed',
                    'session',
                    null,
                    'Failed IMAP login attempt for username: ' . $username
                );
            } else {
                // Failed login
                $error_message = __('login_failed');

                // Log failed login attempt
                logAudit(
                    null, 
                    $username, 
                    'login_failed', 
                    'session', 
                    null, 
                    'Failed login attempt for username: ' . $username
                );
            }

        } catch (Exception $e) {
            error_log('Login error: ' . $e->getMessage());
            $error_message = __('login_error');
        }
    }
}
?>
<!DOCTYPE html>
<html lang="<?php echo htmlspecialchars(currentLang()); ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars(__('login_title')); ?> - <?php echo htmlspecialchars(__('app_title')); ?></title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }

        .login-container {
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            width: 100%;
            max-width: 400px;
            padding: 40px;
        }

        .login-header {
            text-align: center;
            margin-bottom: 30px;
        }

        .login-header i {
            font-size: 48px;
            color: #667eea;
            margin-bottom: 10px;
        }

        .login-header h1 {
            font-size: 24px;
            color: #333;
            margin-bottom: 5px;
        }

        .login-header p {
            color: #666;
            font-size: 14px;
        }

        .alert {
            padding: 12px 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            font-size: 14px;
        }

        .alert-error {
            background: #fee;
            border: 1px solid #fcc;
            color: #c33;
        }

        .alert-success {
            background: #efe;
            border: 1px solid #cfc;
            color: #3c3;
        }

        .form-group {
            margin-bottom: 20px;
        }

        .form-group label {
            display: block;
            margin-bottom: 5px;
            color: #333;
            font-weight: 500;
            font-size: 14px;
        }

        .form-group input {
            width: 100%;
            padding: 12px 15px;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 14px;
            transition: border-color 0.3s;
        }

        .form-group input:focus {
            outline: none;
            border-color: #667eea;
        }

        .btn-login {
            width: 100%;
            padding: 12px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s;
        }

        .btn-login:hover {
            transform: translateY(-2px);
        }

        .btn-login:active {
            transform: translateY(0);
        }

        .login-footer {
            text-align: center;
            margin-top: 20px;
            color: #999;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-header">
            <i class="fas fa-envelope-circle-check"></i>
            <h1><?php echo htmlspecialchars(__('app_title')); ?></h1>
            <p><?php echo htmlspecialchars(__('login_subtitle')); ?></p>
        </div>

        <?php if ($error_message): ?>
            <div class="alert alert-error">
                <i class="fas fa-exclamation-triangle"></i>
                <?php echo htmlspecialchars($error_message); ?>
            </div>
        <?php endif; ?>

        <?php if ($success_message): ?>
            <div class="alert alert-success">
                <i class="fas fa-check-circle"></i>
                <?php echo htmlspecialchars($success_message); ?>
            </div>
        <?php endif; ?>

        <form method="POST" action="login.php">
            <div class="form-group">
                <label for="username">
                    <i class="fas fa-user"></i> <?php echo htmlspecialchars(__('login_username')); ?>
                </label>
                <input 
                    type="text" 
                    id="username" 
                    name="username" 
                    required 
                    autofocus
                    autocomplete="username"
                >
            </div>

            <div class="form-group">
                <label for="password">
                    <i class="fas fa-lock"></i> <?php echo htmlspecialchars(__('login_password')); ?>
                </label>
                <input 
                    type="password" 
                    id="password" 
                    name="password" 
                    required
                    autocomplete="current-password"
                >
            </div>

            <button type="submit" name="login" class="btn-login">
                <i class="fas fa-sign-in-alt"></i> <?php echo htmlspecialchars(__('login_button')); ?>
            </button>
        </form>

        <div class="login-footer">
            <?php echo htmlspecialchars(__('app_title')); ?> v<?php echo htmlspecialchars(APP_VERSION); ?>
        </div>
    </div>
</body>
</html>
