<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/security.php';

$errors = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = strtolower(trim($_POST['email'] ?? ''));
    $password = (string)($_POST['password'] ?? '');

    if (!is_valid_email($email)) $errors[] = "Invalid email.";
    if ($password === '') $errors[] = "Password is required.";

    if (!$errors) {
        if (is_locked_out($email)) {
            $errors[] = "Too many failed attempts. Try again after " . LOCKOUT_MINUTES . " minutes.";
        } else {
            $stmt = db()->prepare("SELECT id, full_name, email, password_hash, role, profile_photo FROM users WHERE email = ?");
            $stmt->execute([$email]);
            $user = $stmt->fetch();

            $ok = $user && password_verify($password, $user['password_hash']);

            record_login_attempt($email, $ok);

            if ($ok) {
                $_SESSION['user'] = [
                    'id' => $user['id'],
                    'full_name' => $user['full_name'],
                    'email' => $user['email'],
                    'role' => $user['role'],
                    'profile_photo' => $user['profile_photo'],
                ];

                // Role-based redirect
                if ($user['role'] === 'admin') {
                    header('Location: ' . BASE_URL . '/admin.php');
                } else {
                    header('Location: ' . BASE_URL . '/dashboard.php');
                }
                exit;
            } else {
                $errors[] = "Invalid email or password.";
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
</head>
<body>
<div class="container">
  <div class="card">
    <div class="header">
      <h1>Welcome back</h1>
      <p>Log in to continue</p>
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

    <form method="post">
      <div class="field">
        <label>Email</label>
        <input class="input" name="email" type="email" required>
      </div>

      <div class="field">
        <label>Password</label>
        <input class="input" name="password" type="password" required>
      </div>

      <button class="btn" type="submit">Login</button>
    </form>

    <a class="link" href="<?= BASE_URL ?>/registration.php">Create an account</a>

    <div class="help" style="margin-top:14px; text-align:center;">
      <b>Default Admin:</b> admin@site.local / Admin@12345
    </div>
  </div>
</div>
</body>
</html>
