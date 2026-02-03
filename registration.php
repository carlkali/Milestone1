<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/security.php';

$errors = [];
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $full_name = trim($_POST['full_name'] ?? '');
    $email     = strtolower(trim($_POST['email'] ?? ''));
    $phone     = trim($_POST['phone'] ?? '');
    $password  = $_POST['password'] ?? '';

    if ($full_name === '') $errors[] = "Full name required.";
    if (!is_valid_email($email)) $errors[] = "Invalid email.";
    if (!is_valid_phone($phone)) $errors[] = "Invalid phone number.";
    if (strlen($password) < 8) $errors[] = "Password must be at least 8 characters.";

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

                $success = "Registration successful. You may now log in.";
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
</head>
<body>
<div class="container">
  <div class="card">
    <div class="header">
      <h1>Create Account</h1>
    </div>

    <?php if (!empty($success)): ?>
      <div class="alert success"><?= htmlspecialchars($success) ?></div>
    <?php endif; ?>

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

      <div class="field">
        <label>Full Name</label>
        <input name="full_name" required>
      </div>

      <div class="field">
        <label>Email</label>
        <input type="email" name="email" required>
      </div>

      <div class="field">
        <label>Phone</label>
        <input name="phone" placeholder="09XXXXXXXXX" required>
      </div>

      <div class="field">
        <label>Password</label>
        <input type="password" name="password" minlength="8" required>
      </div>

      <button type="submit">Register</button>
    </form>

    <a class="link" href="<?= BASE_URL ?>/login.php">Already have an account?</a>
  </div>
</div>

<script>
  const fileInput = document.getElementById('profile_photo');
  const preview = document.getElementById('avatarPreview');
  const fileName = document.getElementById('fileName');

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
</script>

</body>
</html>
