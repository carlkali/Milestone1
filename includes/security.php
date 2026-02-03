<?php
declare(strict_types=1);

require_once __DIR__ . '/db.php';

function is_valid_email(string $email): bool {
    return (bool)filter_var($email, FILTER_VALIDATE_EMAIL);
}

// PH-style phone validation
function is_valid_phone(string $phone): bool {
    return (bool)preg_match('/^(09\d{9}|\+63\d{10})$/', $phone);
}

function client_ip(): string {
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

function handle_profile_upload(array $file): ?string {
    global $ALLOWED_IMAGE_MIMES;

    if (($file['error'] ?? UPLOAD_ERR_NO_FILE) === UPLOAD_ERR_NO_FILE) {
        return null;
    }

    if ($file['error'] !== UPLOAD_ERR_OK) {
        throw new RuntimeException("Upload failed.");
    }

    if ($file['size'] > MAX_UPLOAD_BYTES) {
        throw new RuntimeException("Image too large (max 2MB).");
    }

    $tmp = $file['tmp_name'];
    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $mime = $finfo->file($tmp);

    if (!in_array($mime, $ALLOWED_IMAGE_MIMES, true)) {
        throw new RuntimeException("Invalid image type.");
    }

    $ext = match ($mime) {
        'image/jpeg' => 'jpg',
        'image/png'  => 'png',
        'image/webp' => 'webp',
        default => 'bin'
    };

    $name = bin2hex(random_bytes(16)) . "." . $ext;
    $destDir = __DIR__ . '/../uploads/profiles';

    if (!is_dir($destDir)) {
        mkdir($destDir, 0755, true);
    }

    $dest = $destDir . '/' . $name;

    if (!move_uploaded_file($tmp, $dest)) {
        throw new RuntimeException("Failed to save image.");
    }

    return 'uploads/profiles/' . $name;
}

function record_login_attempt(string $email, bool $success): void {
    $stmt = db()->prepare("INSERT INTO login_attempts (email, ip_address, success) VALUES (?, ?, ?)");
    $stmt->execute([$email, client_ip(), $success ? 1 : 0]);
}

function is_locked_out(string $email): bool {
    $stmt = db()->prepare("
        SELECT COUNT(*) AS failed
        FROM login_attempts
        WHERE email = ?
          AND success = 0
          AND attempted_at > (NOW() - INTERVAL ? MINUTE)
    ");
    $stmt->execute([$email, LOCKOUT_MINUTES]);
    $failed = (int)($stmt->fetch()['failed'] ?? 0);

    return $failed >= MAX_FAILED_ATTEMPTS;
}

