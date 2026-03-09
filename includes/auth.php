<?php
declare(strict_types=1);

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/logger.php';

// Session time out
function check_session_timeout(): void {
    if (empty($_SESSION['user'])) {
        return;
    }

    $lastActivity = $_SESSION['last_activity'] ?? null;

    if ($lastActivity !== null) {
        $elapsed = time() - $lastActivity;

        if ($elapsed > SESSION_TIMEOUT) {
            log_auth('INFO', 'Session timed out due to inactivity', [
                'email'        => $_SESSION['user']['email'],
                'idle_seconds' => $elapsed,
            ]);

            // ✅ Just store the message and clear user data
            // Do NOT destroy/restart session — config.php already started it
            $_SESSION['timeout_msg'] = "You were logged out after " . SESSION_TIMEOUT_MINS . " minutes of inactivity.";
            unset($_SESSION['user']);
            unset($_SESSION['last_activity']);

            header('Location: ' . BASE_URL . '/login.php');
            exit;
        }
    }

    $_SESSION['last_activity'] = time();
}

function require_login(): void {
    check_session_timeout();
    if (empty($_SESSION['user'])) {
        header('Location: ' . BASE_URL . '/login.php');
        exit;
    }
}

function require_admin(): void {
    require_login();
    if (($_SESSION['user']['role'] ?? '') !== 'admin') {
        header('Location: ' . BASE_URL . '/dashboard.php');
        exit;
    }
}