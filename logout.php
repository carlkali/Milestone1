<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/config.php';
require_once __DIR__ . '/includes/logger.php';

if (!empty($_SESSION['user'])) {
    log_auth('INFO', 'User logged out', ['email' => $_SESSION['user']['email']]);
}
session_destroy();
header('Location: ' . BASE_URL . '/login.php');
exit;
