<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/security.php';
require_once __DIR__ . '/includes/logger.php';

require_login();

$userId = (int)$_SESSION['user']['id'];

// Fetch fresh user data from DB
$stmt = db()->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$userId]);
$user = $stmt->fetch();

$errors  = [];
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validate_csrf_token()) {
        $errors[] = "Invalid request. Please refresh and try again.";
    } else {
        $fullName = trim($_POST['full_name'] ?? '');
        $phone    = trim($_POST['phone'] ?? '');
        $password = $_POST['password'] ?? '';
        $confirm  = $_POST['confirm_password'] ?? '';

        if ($fullName === '')            $errors[] = "Full name is required.";
        if (strlen($fullName) > 120)     $errors[] = "Name must be under 120 characters.";
        if ($phone === '')               $errors[] = "Phone number is required.";
        if (!preg_match('/^\+?[0-9\s\-]{7,30}$/', $phone)) $errors[] = "Invalid phone number format.";

        if ($password !== '') {
            if (strlen($password) < 8)   $errors[] = "Password must be at least 8 characters.";
            if ($password !== $confirm)  $errors[] = "Passwords do not match.";
        }

        if (!$errors) {
            $stmt = db()->prepare("SELECT id FROM users WHERE phone = ? AND id != ?");
            $stmt->execute([$phone, $userId]);
            if ($stmt->fetch()) $errors[] = "That phone number is already in use.";
        }

        $profilePhoto = $user['profile_photo'];
        if (!empty($_FILES['profile_photo']['name'])) {
            $file    = $_FILES['profile_photo'];
            $mime    = mime_content_type($file['tmp_name']);
            $allowed = ['image/jpeg', 'image/png'];

            if (!in_array($mime, $allowed, true)) {
                $errors[] = "Profile photo must be JPG or PNG.";
            } elseif ($file['size'] > MAX_UPLOAD_BYTES) {
                $errors[] = "Profile photo must be under 2MB.";
            } else {
                $ext      = $mime === 'image/png' ? 'png' : 'jpg';
                $filename = 'uploads/profiles/' . uniqid('user_', true) . '.' . $ext;
                $destPath = __DIR__ . '/' . $filename;

                if (move_uploaded_file($file['tmp_name'], $destPath)) {
                    if (!empty($user['profile_photo'])) {
                        $oldPath = __DIR__ . '/' . $user['profile_photo'];
                        if (file_exists($oldPath)) unlink($oldPath);
                    }
                    $profilePhoto = $filename;
                } else {
                    $errors[] = "Failed to upload profile photo.";
                }
            }
        }

        if (!$errors) {
            if ($password !== '') {
                $hash = password_hash($password, PASSWORD_ARGON2ID);
                $stmt = db()->prepare("
                    UPDATE users SET full_name=?, phone=?, password_hash=?, profile_photo=? WHERE id=?
                ");
                $stmt->execute([$fullName, $phone, $hash, $profilePhoto, $userId]);
            } else {
                $stmt = db()->prepare("
                    UPDATE users SET full_name=?, phone=?, profile_photo=? WHERE id=?
                ");
                $stmt->execute([$fullName, $phone, $profilePhoto, $userId]);
            }

            $_SESSION['user']['full_name']     = $fullName;
            $_SESSION['user']['profile_photo'] = $profilePhoto;

            log_auth('INFO', 'Profile updated', [
                'user_id' => $userId,
                'email'   => $user['email'],
            ]);

            $success = "Profile updated successfully.";

            $stmt = db()->prepare("SELECT * FROM users WHERE id = ?");
            $stmt->execute([$userId]);
            $user = $stmt->fetch();
        }
    }
}
?>
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Edit Profile</title>
  <link rel="stylesheet" href="<?= BASE_URL ?>/assets/styles.css">
</head>
<body class="dashboard">

<header class="dash-header">
  <a class="logout" href="<?= BASE_URL ?>/dashboard.php">← Back to Profile</a>
  <a class="logout" href="<?= BASE_URL ?>/logout.php">Logout</a>
</header>

<main class="dash-main">
  <div style="width:100%; max-width:600px; margin:0 auto;">

    <!-- Profile Header Card (same format as profile page) -->
    <div class="admin-card" style="margin-bottom:24px;">
      <div style="display:flex; align-items:center; gap:20px;">

        <!-- Avatar -->
        <div style="flex-shrink:0;">
          <?php if (!empty($user['profile_photo'])): ?>
            <img src="<?= BASE_URL ?>/<?= htmlspecialchars($user['profile_photo']) ?>"
                 alt="Profile"
                 style="width:80px; height:80px; border-radius:50%; object-fit:cover; border:3px solid #e5e7eb;">
          <?php else: ?>
            <div style="width:80px; height:80px; border-radius:50%; background:#e5e7eb;
                        display:flex; align-items:center; justify-content:center;
                        font-size:32px; font-weight:800; color:#6b7280; border:3px solid #e5e7eb;">
              <?= strtoupper(substr($user['full_name'], 0, 1)) ?>
            </div>
          <?php endif; ?>
        </div>

        <!-- Name / Email / Role -->
        <div style="flex:1; min-width:0;">
          <div style="font-size:20px; font-weight:800; color:#111827; margin-bottom:4px;">
            <?= htmlspecialchars($user['full_name']) ?>
          </div>
          <div style="font-size:13px; color:#6b7280; margin-bottom:2px;">
            <?= htmlspecialchars($user['email']) ?>
          </div>
          <div style="font-size:12px; color:#9ca3af; text-transform:capitalize;">
            <?= htmlspecialchars($user['role']) ?>
          </div>
        </div>

        <!-- Editing badge -->
        <div style="flex-shrink:0;">
          <span style="display:inline-block; padding:8px 16px;
                       background:#f3f4f6; color:#374151;
                       border-radius:10px; font-size:13px; font-weight:700;
                       border:1px solid #e5e7eb;">
            Editing
          </span>
        </div>

      </div>
    </div>

    <!-- Flash messages -->
    <?php if ($success): ?>
      <div class="alert success" style="margin-bottom:16px;"><?= htmlspecialchars($success) ?></div>
    <?php endif; ?>
    <?php if ($errors): ?>
      <div class="alert error" style="margin-bottom:16px;">
        <ul><?php foreach ($errors as $e): ?><li><?= htmlspecialchars($e) ?></li><?php endforeach; ?></ul>
      </div>
    <?php endif; ?>

    <!-- Edit Form Card -->
    <div class="admin-card" style="margin-bottom:40px;">
      <h2 class="admin-title">Edit Profile</h2>

      <form method="post" enctype="multipart/form-data">
        <?= csrf_field() ?>

        <!-- Basic Info -->
        <div style="display:flex; flex-direction:column; gap:14px;">

          <div class="field">
            <label style="font-size:12px; font-weight:700; color:#374151; display:block; margin-bottom:6px;">
              Full Name
            </label>
            <input type="text" name="full_name" maxlength="120" required
              value="<?= htmlspecialchars($user['full_name']) ?>"
              style="width:100%; padding:11px 14px; border-radius:10px;
                     border:1px solid #d1d5db; font-size:14px; box-sizing:border-box;">
          </div>

          <div class="field">
            <label style="font-size:12px; font-weight:700; color:#374151; display:block; margin-bottom:6px;">
              Phone
            </label>
            <input type="text" name="phone" maxlength="30" required
              value="<?= htmlspecialchars($user['phone']) ?>"
              style="width:100%; padding:11px 14px; border-radius:10px;
                     border:1px solid #d1d5db; font-size:14px; box-sizing:border-box;">
          </div>

          <div class="field">
            <label style="font-size:12px; font-weight:700; color:#374151; display:block; margin-bottom:6px;">
              Email <span style="color:#9ca3af; font-weight:400;">(cannot be changed)</span>
            </label>
            <input type="email" value="<?= htmlspecialchars($user['email']) ?>" disabled
              style="width:100%; padding:11px 14px; border-radius:10px;
                     border:1px solid #e5e7eb; font-size:14px; background:#f9fafb;
                     color:#9ca3af; box-sizing:border-box;">
          </div>

        </div>

        <hr style="border:none; border-top:1px solid #e5e7eb; margin:20px 0;">

        <!-- Password -->
        <h3 style="font-size:14px; font-weight:700; color:#374151; margin:0 0 14px;">
          Change Password <span style="color:#9ca3af; font-weight:400;">(leave blank to keep current)</span>
        </h3>
        <div style="display:flex; flex-direction:column; gap:14px;">

          <div class="field">
            <label style="font-size:12px; font-weight:700; color:#374151; display:block; margin-bottom:6px;">
              New Password
            </label>
            <input type="password" name="password" maxlength="128"
              style="width:100%; padding:11px 14px; border-radius:10px;
                     border:1px solid #d1d5db; font-size:14px; box-sizing:border-box;">
          </div>

          <div class="field">
            <label style="font-size:12px; font-weight:700; color:#374151; display:block; margin-bottom:6px;">
              Confirm New Password
            </label>
            <input type="password" name="confirm_password" maxlength="128"
              style="width:100%; padding:11px 14px; border-radius:10px;
                     border:1px solid #d1d5db; font-size:14px; box-sizing:border-box;">
          </div>

        </div>

        <hr style="border:none; border-top:1px solid #e5e7eb; margin:20px 0;">

        <!-- Profile Photo -->
        <h3 style="font-size:14px; font-weight:700; color:#374151; margin:0 0 14px;">
          Profile Photo <span style="color:#9ca3af; font-weight:400;">(leave blank to keep current)</span>
        </h3>

        <div style="display:flex; align-items:center; gap:16px; margin-bottom:16px;">
          <!-- Current photo preview -->
          <?php if (!empty($user['profile_photo'])): ?>
            <img src="<?= BASE_URL ?>/<?= htmlspecialchars($user['profile_photo']) ?>"
                 style="width:56px; height:56px; border-radius:50%; object-fit:cover; border:2px solid #e5e7eb; flex-shrink:0;">
          <?php else: ?>
            <div style="width:56px; height:56px; border-radius:50%; background:#e5e7eb;
                        display:flex; align-items:center; justify-content:center;
                        font-size:22px; font-weight:800; color:#6b7280; flex-shrink:0;">
              <?= strtoupper(substr($user['full_name'], 0, 1)) ?>
            </div>
          <?php endif; ?>

          <input type="file" name="profile_photo" accept="image/jpeg,image/png"
            style="font-size:13px; color:#374151;">
        </div>
        <p style="font-size:12px; color:#9ca3af; margin:0 0 20px;">JPG or PNG, max 2MB.</p>

        <!-- Submit -->
        <button type="submit"
          style="width:100%; padding:13px; background:linear-gradient(135deg,#7c3aed,#6d28d9);
                 color:#fff; border:none; border-radius:12px; font-size:15px;
                 font-weight:700; cursor:pointer; margin:0;">
          Save Changes
        </button>

      </form>
    </div>

  </div>
</main>
</body>
</html>