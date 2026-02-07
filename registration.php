<?php
declare(strict_types=1);

// Include security configuration and helper functions
require_once __DIR__ . '/includes/security.php';

// Initialize error messages and success flag
$errors = [];
$success = '';

// Check if form was submitted via POST
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Sanitize and retrieve form inputs
    $full_name = trim($_POST['full_name'] ?? '');
    $email     = strtolower(trim($_POST['email'] ?? '')); // Convert email to lowercase
    $phone     = trim($_POST['phone'] ?? '');
    $password  = $_POST['password'] ?? ''; // Don't trim password

    // VALIDATION: Check all required fields
    if ($full_name === '') $errors[] = "Full name required.";
    if (!is_valid_email($email)) $errors[] = "Invalid email.";
    if (!is_valid_phone($phone)) $errors[] = "Invalid phone number.";
    if (strlen($password) < 8) $errors[] = "Password must be at least 8 characters.";

    // Proceed only if all validation passed
    if (!$errors) {
        try {
            // SECURITY: Handle profile photo upload with type detection
            $photo = handle_profile_upload($_FILES['profile_photo'] ?? []);

            // Check if email already exists in database
            $stmt = db()->prepare("SELECT id FROM users WHERE email = ?");
            $stmt->execute([$email]);

            if ($stmt->fetch()) {
                // Email already registered - show error
                $errors[] = "Email already registered.";
            } else {
                // SECURITY: Hash password with bcrypt (includes automatic salting)
                $hash = password_hash($password, PASSWORD_BCRYPT);

                // Insert new user into database
                $stmt = db()->prepare("
                    INSERT INTO users (full_name, email, phone, password_hash, profile_photo)
                    VALUES (?, ?, ?, ?, ?)
                ");
                $stmt->execute([$full_name, $email, $phone, $hash, $photo]);

                // Set success flag to show success message
                $success = true;
            }
        } catch (Throwable $e) {
            // Catch any errors (file upload, database, etc.)
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
    /* Success message styling with green theme and centered content */
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
    /* Login button styling within success message */
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
    /* Error alert styling with red theme */
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
    /* Custom bullet point for error messages */
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
    
    <!-- Show success message if registration successful -->
    <?php if ($success): ?>
      <div class="alert success">
        <h2>Registration Successful!</h2>
        <p>Your account has been created successfully.</p>
        <p>You can now log in with your credentials.</p>
        <a href="<?= BASE_URL ?>/login.php" class="btn-login">Go to Login Page</a>
      </div>
    <?php else: ?>
      
      <!-- Show form header only when form is visible -->
       <div class="header">
         <h1>Create Account</h1>
       </div>

      <!-- Display validation errors if any -->
      <?php if (!empty($errors)): ?>
        <div class="alert error">
          <ul>
            <?php foreach ($errors as $e): ?>
              <li><?= htmlspecialchars($e) ?></li>
            <?php endforeach; ?>
          </ul>
        </div>
      <?php endif; ?>

      <!-- Registration form - hidden after successful registration -->
      <form method="post" enctype="multipart/form-data">
        <!-- Profile photo upload section -->
        <div class="avatar-box">
          <div class="avatar" id="avatarPreview">
            <span>Photo</span>
          </div>
          <!-- SECURITY: File input with accept attribute to limit file types -->
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

          <!-- Display selected filename -->
          <div class="file-name" id="fileName">
            No file selected
          </div>
        </div>

        <!-- Full name input field -->
        <div class="field">
          <label>Full Name</label>
          <input name="full_name" required>
        </div>

        <!-- Email input field with HTML5 validation -->
        <div class="field">
          <label>Email</label>
          <input type="email" name="email" required>
        </div>

        <!-- Phone input with pattern validation for PH phone numbers -->
        <div class="field">
          <label>Phone</label>
          <!-- VALIDATION: Pattern matches 09XXXXXXXXX or +63XXXXXXXXXX -->
          <input name="phone" placeholder="09XXXXXXXXX" pattern="^(09\d{9}|\+63\d{10})$" title="Format: 09XXXXXXXXX or +63XXXXXXXXXX" required>
        </div>

        <!-- Password input with minimum length requirement -->
        <div class="field">
          <label>Password</label>
          <input type="password" name="password" minlength="8" required>
        </div>

        <!-- Submit button -->
        <button type="submit">Register</button>
      </form>

      <!-- Link to login page -->
      <a class="link" href="<?= BASE_URL ?>/login.php">Already have an account? Login here.</a>
    
    <?php endif; ?>
  </div>
</div>

<script>
  // JavaScript for image preview functionality
  const fileInput = document.getElementById('profile_photo');
  const preview = document.getElementById('avatarPreview');
  const fileName = document.getElementById('fileName');

  if (fileInput) {
    fileInput.addEventListener('change', () => {
      const file = fileInput.files[0];
      
      // No file selected - reset display
      if (!file) {
        fileName.textContent = "No file selected";
        return;
      }

      // Display selected filename
      fileName.textContent = file.name;

      // Create and display image preview
      const img = document.createElement('img');
      img.src = URL.createObjectURL(file);
      preview.innerHTML = '';
      preview.appendChild(img);
    });
  }
</script>

</body>
</html>