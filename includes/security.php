<?php
declare(strict_types=1);

// Include database connection
require_once __DIR__ . '/db.php';

/**
 * VALIDATION: Email format validation
 * Uses PHP's built-in filter to validate email format
 * @param string $email - Email address to validate
 * @return bool - True if valid email format, false otherwise
 */
function is_valid_email(string $email): bool {
    return (bool)filter_var($email, FILTER_VALIDATE_EMAIL);
}

/**
 * VALIDATION: Philippine phone number validation
 * Accepts two formats:
 * - 09XXXXXXXXX (11 digits starting with 09)
 * - +63XXXXXXXXXX (13 characters starting with +63)
 * @param string $phone - Phone number to validate
 * @return bool - True if valid PH phone format, false otherwise
 */
function is_valid_phone(string $phone): bool {
    return (bool)preg_match('/^(09\d{9}|\+63\d{10})$/', $phone);
}

/**
 * Get client's IP address from server variables
 * @return string - Client IP address or '0.0.0.0' if not available
 */
function client_ip(): string {
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

/**
 * SECURITY: Handle profile photo upload with type detection
 * Validates file type using MIME detection (not just extension)
 * Generates random filename to prevent overwrites
 * @param array $file - File array from $_FILES
 * @return string|null - Relative path to uploaded file or null if no file
 * @throws RuntimeException - On upload errors
 */
function handle_profile_upload(array $file): ?string {
    global $ALLOWED_IMAGE_MIMES;

    // Check if no file was uploaded (optional upload)
    if (($file['error'] ?? UPLOAD_ERR_NO_FILE) === UPLOAD_ERR_NO_FILE) {
        return null;
    }

    // Check for upload errors
    if ($file['error'] !== UPLOAD_ERR_OK) {
        throw new RuntimeException("Upload failed.");
    }

    // SECURITY: Validate file size (must be under MAX_UPLOAD_BYTES)
    if ($file['size'] > MAX_UPLOAD_BYTES) {
        throw new RuntimeException("Image too large (max 2MB).");
    }

    // Get temporary file path
    $tmp = $file['tmp_name'];
    
    // SECURITY: Detect actual MIME type using fileinfo (not trusting client)
    // This prevents uploading malicious files disguised as images
    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $mime = $finfo->file($tmp);

    // SECURITY: Validate against whitelist of allowed MIME types
    if (!in_array($mime, $ALLOWED_IMAGE_MIMES, true)) {
        throw new RuntimeException("Invalid image type.");
    }

    // Determine file extension based on validated MIME type
    $ext = match ($mime) {
        'image/jpeg' => 'jpg',
        'image/png'  => 'png',
        'image/webp' => 'webp',
        default => 'bin'
    };

    // SECURITY: Generate random filename to prevent overwrites and guessing
    $name = bin2hex(random_bytes(16)) . "." . $ext;
    $destDir = __DIR__ . '/../uploads/profiles';

    // Create directory if it doesn't exist
    if (!is_dir($destDir)) {
        mkdir($destDir, 0755, true);
    }

    $dest = $destDir . '/' . $name;

    // Move uploaded file to permanent location
    if (!move_uploaded_file($tmp, $dest)) {
        throw new RuntimeException("Failed to save image.");
    }

    // Return relative path for storing in database
    return 'uploads/profiles/' . $name;
}

/**
 * SECURITY: Record login attempt for brute-force protection
 * Logs both successful and failed login attempts with IP address
 * @param string $email - Email address of login attempt
 * @param bool $success - Whether login was successful
 * @return void
 */
function record_login_attempt(string $email, bool $success): void {
    $stmt = db()->prepare("INSERT INTO login_attempts (email, ip_address, success) VALUES (?, ?, ?)");
    $stmt->execute([$email, client_ip(), $success ? 1 : 0]);
}

/**
 * SECURITY: Check if account is locked out due to failed attempts
 * Counts failed login attempts within the lockout time window
 * @param string $email - Email address to check
 * @return bool - True if account is locked out, false otherwise
 */
function is_locked_out(string $email): bool {
    // Query failed attempts within the lockout window
    $stmt = db()->prepare("
        SELECT COUNT(*) AS failed
        FROM login_attempts
        WHERE email = ?
          AND success = 0
          AND attempted_at > (NOW() - INTERVAL ? MINUTE)
    ");
    $stmt->execute([$email, LOCKOUT_MINUTES]);
    $failed = (int)($stmt->fetch()['failed'] ?? 0);

    // Lock out if failed attempts exceed threshold
    return $failed >= MAX_FAILED_ATTEMPTS;
}