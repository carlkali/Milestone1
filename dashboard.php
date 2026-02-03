<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/auth.php';
require_login();

$user = $_SESSION['user'];
?>
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>User Dashboard</title>
  <link rel="stylesheet" href="<?= BASE_URL ?>/assets/styles.css">
</head>
<body class="dashboard">

<!-- Header -->
<header class="dash-header">
  <a class="logout" href="<?= BASE_URL ?>/logout.php">Logout</a>
</header>

<!-- Content -->
<div class="profile-wrap">
  <div class="profile-card">

    <div class="profile-avatar">
  <?php if (!empty($_SESSION['user']['profile_photo'])): ?>
    <img
      src="<?= BASE_URL ?>/<?= htmlspecialchars($_SESSION['user']['profile_photo']) ?>"
      alt="Profile"
    >
  <?php else: ?>
    <span style="font-size:32px; font-weight:800; color:#6b7280;">
      <?= strtoupper(substr($_SESSION['user']['full_name'], 0, 1)) ?>
    </span>
  <?php endif; ?>
</div>


    <div class="profile-name">
      <?= htmlspecialchars($_SESSION['user']['full_name']) ?>
    </div>

    <div class="profile-role">
      Role: <?= htmlspecialchars($_SESSION['user']['role']) ?>
    </div>

  </div>
</div>

</body>
</html>

