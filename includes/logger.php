<?php
declare(strict_types=1);

define('LOG_DIR', __DIR__ . '/../logs/');

function ensure_log_dir(): void {
    if (!is_dir(LOG_DIR)) {
        mkdir(LOG_DIR, 0755, true);
    }
}

/**
 * Send a log line to SolarWinds Papertrail via HTTPS.
 * Uses a Bearer token and posts to their collector endpoint.
 */
function send_https_syslog(string $message): void {
    if (!defined('SYSLOG_ENDPOINT') || !defined('SYSLOG_TOKEN')) return;

    $ch = curl_init(SYSLOG_ENDPOINT);
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $message,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 3,
        CURLOPT_HTTPHEADER     => [
            'Content-Type: application/octet-stream',
            'Authorization: Bearer ' . SYSLOG_TOKEN,
        ],
    ]);
    curl_exec($ch);
}

function write_log(string $channel, string $level, string $message, array $context = []): void {
    ensure_log_dir();

    $timestamp = date('Y-m-d H:i:s');
    $ip        = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $userId    = $_SESSION['user']['id']    ?? 'guest';
    $userEmail = $_SESSION['user']['email'] ?? 'guest';

    $contextStr = '';
    if (!empty($context)) {
        $pairs = [];
        foreach ($context as $k => $v) {
            if (is_bool($v))                       { $v = $v ? 'true' : 'false'; }
            elseif ($v === null)                   { $v = 'null'; }
            elseif (is_array($v) || is_object($v)) {
                $json = json_encode($v, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
                $v = ($json === false) ? '[unencodable]' : $json;
            } else { $v = (string)$v; }
            $v = str_replace(["\r", "\n", "\t"], ['\\r', '\\n', '\\t'], $v);
            $pairs[] = $k . '=' . $v;
        }
        $contextStr = ' | ' . implode(', ', $pairs);
    }

    $line = "[{$timestamp}] [{$level}] [channel:{$channel}] [IP:{$ip}] [User:{$userId}({$userEmail})] {$message}{$contextStr}";

    // 1. Write to flat log file
    $file = LOG_DIR . $channel . '_' . date('Y-m-d') . '.log';
    file_put_contents($file, $line . PHP_EOL, FILE_APPEND | LOCK_EX);

    // 2. Forward to remote log collector via HTTPS (if enabled)
    if (defined('SYSLOG_ENABLED') && SYSLOG_ENABLED === true) {
        send_https_syslog($line);
    }
}

function log_auth(string $level, string $message, array $context = []): void {
    write_log('auth', $level, $message, $context);
}

function log_transaction(string $level, string $message, array $context = []): void {
    write_log('transaction', $level, $message, $context);
}

function log_admin(string $level, string $message, array $context = []): void {
    write_log('admin', $level, $message, $context);
}