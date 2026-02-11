<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/security.php';

$errors = [];
$success = '';

$full_name = '';
$email = '';
$phone = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Capture inputs from POST
    $full_name = trim($_POST['full_name'] ?? '');
    $email     = strtolower(trim($_POST['email'] ?? ''));
    $phone     = trim($_POST['phone'] ?? '');
    $password  = $_POST['password'] ?? '';

    // Validation
    if ($full_name === '') $errors[] = "Full name required.";
    if (!is_valid_email($email)) $errors[] = "Invalid email.";
    if (!is_valid_phone($phone)) $errors[] = "Invalid phone number.";
    
    // Password validation
      $password_errors = validate_password_strength($password);
    if ($password_errors) {
    // Generic user-facing message
    $errors[] = "Password does not meet security requirements. Please review the requirements below.";
    
}

    if (!$errors) {
        try {
            $photo = handle_profile_upload($_FILES['profile_photo'] ?? []);

            $stmt = db()->prepare("SELECT id FROM users WHERE email = ?");
            $stmt->execute([$email]);

            if ($stmt->fetch()) {
                $errors[] = "Email already registered.";
            } else {
                $hash = password_hash($password, PASSWORD_BCRYPT);

                $stmt = db()->prepare("
                    INSERT INTO users (full_name, email, phone, password_hash, profile_photo)
                    VALUES (?, ?, ?, ?, ?)
                ");
                $stmt->execute([$full_name, $email, $phone, $hash, $photo]);

                $success = true;
            }
        } catch (Throwable $e) {
            $errors[] = $e->getMessage();
        }
    }
}

?>
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Register</title>
  <link rel="stylesheet" href="<?= BASE_URL ?>/assets/styles.css">
  <style>
    .alert.success {
      background-color: #dff0d8;
      border-left: 5px solid #5cb85c;
      color: #3c763d;
      padding: 20px;
      margin-bottom: 20px;
      border-radius: 4px;
      text-align: center;
    }
    .alert.success h2 {
      margin: 0 0 10px 0;
      font-size: 24px;
      color: #3c763d;
    }
    .alert.success p {
      margin: 10px 0;
      font-size: 16px;
    }
    .alert.success .btn-login {
      display: inline-block;
      margin-top: 15px;
      padding: 12px 30px;
      background-color: #5cb85c;
      color: white;
      text-decoration: none;
      border-radius: 4px;
      font-weight: bold;
      transition: background-color 0.3s;
    }
    .alert.success .btn-login:hover {
      background-color: #4cae4c;
    }
    .alert.error {
      background-color: #fce8e8;
      border-left: 5px solid #d9534f;
      color: #a94442;
      padding: 15px 20px;
      margin-bottom: 20px;
      border-radius: 4px;
    }
    .alert.error ul {
      margin: 0;
      padding: 0;
      list-style: none;
    }
    .alert.error li {
      margin: 0;
      padding: 0;
      list-style: none;
    }
    .alert.error li:before {
      content: "• ";
      color: #d9534f;
      font-weight: bold;
      margin-right: 8px;
    }
  </style>
</head>
<body>
<div class="container">
  <div class="card">
    
    <?php if ($success): ?>
      <div class="alert success">
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
        <!-- Profile photo upload section -->
        <div class="avatar-box">
          <div class="avatar" id="avatarPreview">
            <span>Photo</span>
          </div>
          <input
            class="file-input"
            type="file"
            name="profile_photo"
            id="profile_photo"
            accept=".jpg,.jpeg,.png,.webp"
          >

          <label for="profile_photo" class="file-btn">
            Upload profile photo
          </label>

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
          <input type="password" name="password" required>
          <div style="font-size: 11px; color: #6b7280; margin-top: 6px;">
            <strong>Password requirements:</strong>
            <ul style="margin: 4px 0; padding-left: 20px; line-height: 1.6;">
              <li>At least 8 characters</li>
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

      <a class="link" href="<?= BASE_URL ?>/login.php">Already have an account? Login here.</a>
    
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

</body>
</html>