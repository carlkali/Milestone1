<?php
declare(strict_types=1);

// Include database connection
require_once __DIR__ . '/db.php';

// ==================== CSRF PROTECTION ====================

/**
 * Generate a CSRF token and store it in the session
 * Call this once per page load that has forms
 */
function generate_csrf_token(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/**
 * Get the current CSRF token
 */
function get_csrf_token(): string {
    return $_SESSION['csrf_token'] ?? '';
}

/**
 * Validate CSRF token from form submission
 * Call this at the start of POST request handling
 */
function validate_csrf_token(): bool {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        return true; // Only validate POST requests
    }
    
    $submitted_token = $_POST['csrf_token'] ?? '';
    $session_token = $_SESSION['csrf_token'] ?? '';
    
    if (empty($submitted_token) || empty($session_token)) {
        return false;
    }
    
    // Use hash_equals to prevent timing attacks
    return hash_equals($session_token, $submitted_token);
}

/**
 * Output CSRF token as hidden input field
 * Use this in all forms
 */
function csrf_field(): string {
    $token = generate_csrf_token();
    return '<input type="hidden" name="csrf_token" value="' . htmlspecialchars($token) . '">';
}

// ==================== EMAIL & PHONE VALIDATION ====================

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

// ==================== FILE UPLOAD HANDLING ====================

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

// ==================== BRUTE-FORCE PROTECTION ====================

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

// ==================== PASSWORD VALIDATION ====================

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
    
    if (!preg_match('/[!@#$%^&*]/', $password)) {
        $errors[] = "Missing special character";
    }

    if (!preg_match('/^[A-Za-z0-9!@#$%^&*]+$/', $password)) {
        $errors[] = "Password contains invalid characters. Only letters, numbers, and !@#$%^&* are allowed";
    }
    
    if (empty($errors) && is_common_password($password)) {
        $errors[] = "Common password";
    }
    
    return $errors;
}


// ==================== ERROR HANDLING ====================

function register_error_handlers(): void {
    if (DEBUG) {
        // ✅ Local: show full errors on screen
        ini_set('display_errors', '1');
        ini_set('display_startup_errors', '1');
        error_reporting(E_ALL);
    } else {
        // ✅ Production: hide errors, show generic page
        ini_set('display_errors', '0');
        ini_set('display_startup_errors', '0');
        error_reporting(0);

        // Catch unhandled exceptions → show 500 page
        set_exception_handler(function (Throwable $e): void {
            // Log the full error to file
            $logFile = __DIR__ . '/../logs/error_' . date('Y-m-d') . '.log';
            $entry   = sprintf(
                "[%s] [EXCEPTION] %s in %s on line %d\nTrace:\n%s\n\n",
                date('Y-m-d H:i:s'),
                $e->getMessage(),
                $e->getFile(),
                $e->getLine(),
                $e->getTraceAsString()
            );
            file_put_contents($logFile, $entry, FILE_APPEND | LOCK_EX);

            // Show generic 500 page to user
            require __DIR__ . '/../errors/500.php';
            exit;
        });

        // Catch PHP errors → log and show 500 page
        set_error_handler(function (int $severity, string $message, string $file, int $line): bool {
            $logFile = __DIR__ . '/../logs/error_' . date('Y-m-d') . '.log';
            $entry   = sprintf(
                "[%s] [PHP_ERROR] %s in %s on line %d\n\n",
                date('Y-m-d H:i:s'),
                $message,
                $file,
                $line
            );
            file_put_contents($logFile, $entry, FILE_APPEND | LOCK_EX);
            return true;
        });
    }
}