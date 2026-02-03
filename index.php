<?php
require_once __DIR__ . '/includes/config.php';

if (!empty($_SESSION['user'])) {
    if (($_SESSION['user']['role'] ?? '') === 'admin') {
        header('Location: ' . BASE_URL . '/admin.php');
    } else {
        header('Location: ' . BASE_URL . '/dashboard.php');
    }
    exit;
}

header('Location: ' . BASE_URL . '/login.php');
exit;
