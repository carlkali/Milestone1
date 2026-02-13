<?php
declare(strict_types=1);

session_start();

define('DB_HOST', '127.0.0.1');
define('DB_NAME', 'milestone1');
define('DB_USER', 'root');
define('DB_PASS', 'sqlroot'); // XAMPP default

// Your project URL base:
define('BASE_URL', '/secwb/Milestone1');

// brute force settings
define('MAX_FAILED_ATTEMPTS', 5);
define('LOCKOUT_MINUTES', 10);

// upload settings
define('MAX_UPLOAD_BYTES', 2 * 1024 * 1024); // 2MB

$ALLOWED_IMAGE_MIMES = ['image/jpeg', 'image/png'];
