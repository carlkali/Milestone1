<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/config.php';

session_destroy();
header('Location: ' . BASE_URL . '/login.php');
exit;
