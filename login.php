<?php
declare(strict_types=1);

// Include security configuration and helper functions
require_once __DIR__ . '/includes/security.php';

$errors = [];
$success = '';

// Initialize login-related variables
$email = '';

// Check if form was submitted via POST method
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Sanitize and retrieve email from POST data
    $email = strtolower(trim($_POST['email'] ?? ''));
    // Retrieve password 
    $password = (string)($_POST['password'] ?? '');

    // Validate email format using custom validation function
    if (!is_valid_email($email)) {
        $errors[] = "Invalid email format.";
    }
    
    // Check if password field is empty
    if ($password === '') {
        $errors[] = "Password is required.";
    }

    // Proceed only if there are no validation errors
    if (!$errors) {
        // Check if account is locked BEFORE checking credentials
        if (is_locked_out($email)) {
            $errors[] = "The account '" . htmlspecialchars($email) . "' is temporarily locked due to too many failed login attempts. Please try again after " . LOCKOUT_MINUTES . " minutes, or use a different account.";
            $email = '';
        } else {

            
            // Query database for user with matching email
            $stmt = db()->prepare("SELECT id, full_name, email, password_hash, role, profile_photo FROM users WHERE email = ?");
            $stmt->execute([$email]);
            $user = $stmt->fetch();

            // Verify password against stored hash
            $ok = $user && password_verify($password, $user['password_hash']);

            // Record this login attempt for brute-force protection
            record_login_attempt($email, $ok);

            if ($ok) {
                // Login successful - store user data in session
                $_SESSION['user'] = [
                    'id' => $user['id'],
                    'full_name' => $user['full_name'],
                    'email' => $user['email'],
                    'role' => $user['role'],
                    'profile_photo' => $user['profile_photo'],
                ];

                // Role-based redirect to appropriate dashboard
                if ($user['role'] === 'admin') {
                    header('Location: ' . BASE_URL . '/admin.php');
                } else {
                    header('Location: ' . BASE_URL . '/dashboard.php');
                }
                exit;
            } else {
                // Login failed - show generic error message
                $errors[] = "Invalid email or password.";
                $email = '';
            }
        }
    }
}
?>
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Login</title>
  <link rel="stylesheet" href="<?= BASE_URL ?>/assets/styles.css">
  <style>
    /* Error alert styling with red theme */
    .alert.error {
      background-color: #fce8e8;
      border-left: 5px solid #d9534f;
      color: #a94442;
      padding: 15px 20px;
      margin-bottom: 20px;
      border-radius: 4px;
      list-style: none;
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
    /* Success alert styling with green theme */
    .alert.success {
      background-color: #dff0d8;
      border-left: 5px solid #5cb85c;
      color: #3c763d;
      padding: 15px 20px;
      margin-bottom: 20px;
      border-radius: 4px;
    }
  </style>
</head>
<body>
<div class="container">
  <div class="card">
    <div class="header">
      <h1>Welcome back!</h1>
      <p>Log in to continue</p>
    </div>

    <!-- Display success message if exists -->
    <?php if (!empty($success)): ?>
      <div class="alert success"><?= htmlspecialchars($success) ?></div>
    <?php endif; ?>

    <!-- Display error messages if any exist -->
    <?php if (!empty($errors)): ?>
      <div class="alert error">
        <ul>
          <?php foreach ($errors as $e): ?>
            <li><?= htmlspecialchars($e) ?></li>
          <?php endforeach; ?>
        </ul>
      </div>
    <?php endif; ?>

    <!-- Login form -->
    <form method="post">
      <div class="field">
        <label>Email</label>
        <input 
          class="input" 
          name="email" 
          type="email" 
          value="<?= htmlspecialchars($email) ?>"
          required
        >
      </div>

      <div class="field">
        <label>Password</label>
        <input 
          class="input" 
          name="password" 
          type="password" 
          required
        >
      </div>

      <button class="btn" type="submit">Login</button>
    </form>

    <!-- Link to registration page -->
    <a class="link" href="<?= BASE_URL ?>/registration.php">Don't have an account? Register here.</a>
  </div>
</div>
</body>
</html>