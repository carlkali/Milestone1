<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/security.php';
require_once __DIR__ . '/includes/logger.php';

$errors = [];
$success = '';

$full_name = '';
$email = '';
$phone = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    if (!validate_csrf_token()) {
        $errors[] = "Invalid request. Please refresh the page and try again.";
        log_auth('WARNING', 'Registration failed - invalid CSRF token', [
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        ]);
    } else {
        $full_name = trim($_POST['full_name'] ?? '');
        $email     = strtolower(trim($_POST['email'] ?? ''));
        $phone     = trim($_POST['phone'] ?? '');
        $password  = $_POST['password'] ?? '';

        if (!isset($_FILES['profile_photo']) || $_FILES['profile_photo']['error'] === UPLOAD_ERR_NO_FILE) {
            $errors[] = "Profile photo is required.";
        } elseif ($_FILES['profile_photo']['error'] !== UPLOAD_ERR_OK) {
            $errors[] = "File upload failed. Please try again.";
        } elseif ($_FILES['profile_photo']['size'] > MAX_UPLOAD_BYTES) {
            $errors[] = "Image too large (max 2MB).";
        }

        if ($full_name === '') $errors[] = "Full name required.";
        if (!is_valid_email($email)) $errors[] = "Invalid email.";
        if (!is_valid_phone($phone)) $errors[] = "Invalid phone number.";

        $password_errors = validate_password_strength($password);
        if ($password_errors) {
            foreach ($password_errors as $pwd_err) {
                $errors[] = $pwd_err;
            }
        }

        if (!$errors) {
            try {
                $photo = handle_profile_upload($_FILES['profile_photo'] ?? []);

                $stmt = db()->prepare("SELECT id, email, phone FROM users WHERE email = ? OR phone = ? LIMIT 1");
                $stmt->execute([$email, $phone]);
                $existing = $stmt->fetch();

                if ($existing) {
                    if (isset($existing['email']) && strtolower($existing['email']) === $email) {
                        $errors[] = "Email already registered.";
                        log_auth('WARNING', 'Registration failed - email already in use', [
                            'email' => $email,
                        ]);
                    }
                    if (isset($existing['phone']) && $existing['phone'] === $phone) {
                        $errors[] = "Phone number already registered.";
                        log_auth('WARNING', 'Registration failed - phone already in use', [
                            'phone' => $phone,
                        ]);
                    }
                } else {
                    $hash = password_hash($password, PASSWORD_BCRYPT);
                    $stmt = db()->prepare("
                        INSERT INTO users (full_name, email, phone, password_hash, profile_photo)
                        VALUES (?, ?, ?, ?, ?)
                    ");
                    $stmt->execute([$full_name, $email, $phone, $hash, $photo]);
                    log_auth('INFO', 'New user registered', [
                        'email' => $email,
                        'name'  => $full_name,
                    ]);
                    $success = true;
                }
            } catch (Throwable $e) {
                $errors[] = $e->getMessage();
            }
        }
    }
}
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Register</title>
  <link rel="stylesheet" href="<?= BASE_URL ?>/assets/styles.css">
</head>

<body>
<div class="container">
  <div class="card">

    <?php if ($success): ?>
      <div class="alert success success-card">
        <h2>Registration Successful!</h2>
        <p>Your account has been created successfully.</p>
        <p>You can now log in with your credentials.</p>
        <a href="<?= BASE_URL ?>/login.php" class="btn-login">Go to Login Page</a>
      </div>
    <?php else: ?>

      <div class="header">
        <h1>Create Account</h1>
      </div>

      <?php if (!empty($errors)): ?>
        <div class="alert error">
          <ul>
            <?php foreach ($errors as $e): ?>
              <li><?= htmlspecialchars($e) ?></li>
            <?php endforeach; ?>
          </ul>
        </div>
      <?php endif; ?>

      <form method="post" enctype="multipart/form-data">
        <?= csrf_field(); ?>

        <!-- Profile photo upload section -->
        <div class="avatar-box">
          <div class="avatar <?= in_array('Profile photo is required.', $errors, true) ? 'error' : '' ?>" id="avatarPreview">
            <span>Photo</span>
          </div>

          <input
            class="file-input"
            type="file"
            name="profile_photo"
            id="profile_photo"
            accept=".jpg,.jpeg,.png"
          >

          <label for="profile_photo" class="file-btn">
            Upload profile photo <span class="req">*</span>
          </label>

          <div class="help-text">
            Max 2MB. Formats: JPG and PNG
          </div>

          <div class="file-name" id="fileName">
            No file selected
          </div>
        </div>

        <!-- Full name input field -->
        <div class="field">
          <label>Full Name</label>
          <input
            name="full_name"
            value="<?= htmlspecialchars($full_name) ?>"
            required
          >
        </div>

        <!-- Email input field -->
        <div class="field">
          <label>Email</label>
          <input
            type="email"
            name="email"
            value="<?= htmlspecialchars($email) ?>"
            required
          >
        </div>

        <!-- Phone input -->
        <div class="field">
          <label>Phone</label>
          <input
            name="phone"
            value="<?= htmlspecialchars($phone) ?>"
            placeholder="09XXXXXXXXX"
            pattern="^(09\d{9}|\+63\d{10})$"
            title="Format: 09XXXXXXXXX or +63XXXXXXXXXX"
            required
          >
        </div>

        <!-- Password input -->
        <div class="field">
          <label>Password</label>
          <input
            type="password"
            name="password"
            id="passwordInput"
            minlength="8"
            maxlength="128"
            required
          >

          <div class="pw-help">
            <strong>Password requirements:</strong>
            <ul>
              <li>8-128 characters</li>
              <li>One uppercase letter (A-Z)</li>
              <li>One lowercase letter (a-z)</li>
              <li>One number (0-9)</li>
              <li>One special character (!@#$%^&*)</li>
              <li>Must not be a commonly used password</li>
            </ul>
          </div>
        </div>

        <button type="submit">Register</button>
      </form>

      <div class="login-section">
        <p>Already have an account?</p>
        <a href="<?= BASE_URL ?>/login.php" class="login-btn">Login here</a>
      </div>

    <?php endif; ?>
  </div>
</div>

<script>
  const fileInput = document.getElementById('profile_photo');
  const preview = document.getElementById('avatarPreview');
  const fileName = document.getElementById('fileName');

  if (fileInput) {
    fileInput.addEventListener('change', () => {
      const file = fileInput.files[0];

      if (!file) {
        fileName.textContent = "No file selected";
        preview.innerHTML = '<span>Photo</span>';
        return;
      }

      fileName.textContent = file.name;

      const img = document.createElement('img');
      img.src = URL.createObjectURL(file);
      preview.innerHTML = '';
      preview.appendChild(img);
    });
  }
</script>

<script>
  const passwordInput = document.getElementById('passwordInput');

  if (passwordInput) {
    passwordInput.addEventListener('input', function() {
      const password = this.value;
      const length = password.length;

      const hasUpper = /[A-Z]/.test(password);
      const hasLower = /[a-z]/.test(password);
      const hasNumber = /[0-9]/.test(password);
      const hasSpecial = /[!@#$%^&*]/.test(password);
      const hasValidLength = length >= 8 && length <= 128;
      const hasOnlyValidChars = /^[A-Za-z0-9!@#$%^&*]+$/.test(password);

      const isValid = hasUpper && hasLower && hasNumber && hasSpecial && hasValidLength && hasOnlyValidChars;

      if (length > 0) {
        this.classList.toggle('pw-ok', isValid);
        this.classList.toggle('pw-bad', !isValid);
      } else {
        this.classList.remove('pw-ok', 'pw-bad');
      }
    });
  }
</script>

</body>
</html>