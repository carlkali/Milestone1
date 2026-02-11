<?php
declare(strict_types=1);

// Include database connection
require_once __DIR__ . '/db.php';


 // Email format validation
function is_valid_email(string $email): bool {
    return (bool)filter_var($email, FILTER_VALIDATE_EMAIL);
}
// Phone number validation
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

// Handle profile photo upload with type detection
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

    //  Validate file size (must be under MAX_UPLOAD_BYTES)
    if ($file['size'] > MAX_UPLOAD_BYTES) {
        throw new RuntimeException("Image too large (max 2MB).");
    }

    // Get temporary file path
    $tmp = $file['tmp_name'];
    
    // Detect actual MIME type using fileinfo (not trusting client)
    // This prevents uploading malicious files disguised as images
    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $mime = $finfo->file($tmp);

    // Validate against whitelist of allowed MIME types
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

    // Generate random filename to prevent overwrites and guessing
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

// Record login attempt for brute-force protection
function record_login_attempt(string $email, bool $success): void {
    $stmt = db()->prepare("INSERT INTO login_attempts (email, ip_address, success) VALUES (?, ?, ?)");
    $stmt->execute([$email, client_ip(), $success ? 1 : 0]);
}

// Check if account is locked out due to failed attempts
// Counts failed login attempts within the lockout time window
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

// Check against common passwords
function is_common_password(string $password): bool {

    $commonComplexPasswords = [
        'Password1!', 'Password123!', 'Welcome1!', 'Welcome123!',
        'Admin123!', 'Qwerty123!', 'Letmein1!', 'Password!1',
        'Welcome1@', 'Admin1234!', 'Change123!', 'Temp1234!',
        'Login123!', 'Pass1234!', 'Secret123!', 'Test1234!',
    ];
    
    // Case-sensitive comparison (Password1! ≠ password1!)
    return in_array($password, $commonComplexPasswords, true);
}

// VALIDATION: Password strength validation
function validate_password_strength(string $password): array {
    $errors = [];
    
    if (strlen($password) < 8) {
        $errors[] = "Length too short";
    }
    
    if (strlen($password) > 128) {
        $errors[] = "Length too long";
    }
    
    if (!preg_match('/[A-Z]/', $password)) {
        $errors[] = "Missing uppercase";
    }
    
    if (!preg_match('/[a-z]/', $password)) {
        $errors[] = "Missing lowercase";
    }
    
    if (!preg_match('/[0-9]/', $password)) {
        $errors[] = "Missing number";
    }
    
    if (!preg_match('/[^A-Za-z0-9]/', $password)) {
        $errors[] = "Missing special character";
    }
    
    if (empty($errors) && is_common_password($password)) {
        $errors[] = "Common password";
    }
    
    return $errors;
}