<?php
declare(strict_types=1);

// ============================================================
// Logger — writes to logs/ directory
// Three channels: auth, transaction, admin
// ============================================================

define('LOG_DIR', __DIR__ . '/../logs/');

function ensure_log_dir(): void {
    if (!is_dir(LOG_DIR)) {
        mkdir(LOG_DIR, 0755, true);
    }
}

/**
 * Core write function.
 * @param string $channel  'auth' | 'transaction' | 'admin'
 * @param string $level    'INFO' | 'WARNING' | 'ERROR'
 * @param string $message  Human-readable description
 * @param array  $context  Optional extra key=>value pairs
 */
function write_log(string $channel, string $level, string $message, array $context = []): void {
    ensure_log_dir();

    $timestamp = date('Y-m-d H:i:s');
    $ip        = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $userId    = $_SESSION['user']['id']    ?? 'guest';
    $userEmail = $_SESSION['user']['email'] ?? 'guest';

    $contextStr = empty($context)
        ? ''
        : ' | ' . http_build_query($context, '', ', ');

    $line = "[{$timestamp}] [{$level}] [IP:{$ip}] [User:{$userId}({$userEmail})] {$message}{$contextStr}" . PHP_EOL;

    $file = LOG_DIR . $channel . '_' . date('Y-m-d') . '.log';

    file_put_contents($file, $line, FILE_APPEND | LOCK_EX);
}

// ============================================================
// Convenience wrappers
// ============================================================

function log_auth(string $level, string $message, array $context = []): void {
    write_log('auth', $level, $message, $context);
}

function log_transaction(string $level, string $message, array $context = []): void {
    write_log('transaction', $level, $message, $context);
}

function log_admin(string $level, string $message, array $context = []): void {
    write_log('admin', $level, $message, $context);
}