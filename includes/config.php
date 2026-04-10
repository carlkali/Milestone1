<?php
declare(strict_types=1);

date_default_timezone_set('Asia/Manila'); // set timezone for consistent logging

session_start();

define('DB_HOST', '127.0.0.1');
define('DB_NAME', 'milestone1');
define('DB_USER', 'root');
define('DB_PASS', ''); // XAMPP default

// Your project URL base:
define('BASE_URL', 'https://margeret-noninvincible-volubly.ngrok-free.dev/secwb/Milestone1');

// ✅ Environment & Debug -- 
define('APP_ENV', 'production');          // change to 'production' on live server
define('DEBUG',   APP_ENV === 'local');   // true on local, false on production -- should not be updated

// brute force settings
define('MAX_FAILED_ATTEMPTS', 5);
define('LOCKOUT_MINUTES', 10);

// upload settings
define('MAX_UPLOAD_BYTES', 2 * 1024 * 1024); // 2MB

$ALLOWED_IMAGE_MIMES = ['image/jpeg', 'image/png'];

// session timeout settings
define('SESSION_TIMEOUT', 1800);       // 30 minutes in seconds
define('SESSION_TIMEOUT_MINS', 30);    // for display in messages

define('SYSLOG_ENABLED',  true);
define('SYSLOG_ENDPOINT', 'https://logs.collector.ap-01.cloud.solarwinds.com/v1/logs');
define('SYSLOG_TOKEN',    'bcUlMtDWbthE2gt3sB2FCM6LBntD-YrNs95kSra5JlyZ3ncYdHHXiSSDA1vlVYeR7sbG5e4');

// error handling, error 404 and 500
require_once __DIR__ . '/security.php';
register_error_handlers();
