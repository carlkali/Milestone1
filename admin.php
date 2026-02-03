<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/db.php';

require_admin();

$users = db()
  ->query("SELECT id, full_name, email, phone, role, created_at FROM users ORDER BY created_at DESC")
  ->fetchAll();
?>
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Admin Panel</title>
  <link rel="stylesheet" href="<?= BASE_URL ?>/assets/styles.css">
</head>

<body class="dashboard">
  <!-- Header -->
  <header class="dash-header">
    <div class="dash-brand">Admin Panel</div>
    <a class="logout" href="<?= BASE_URL ?>/logout.php">Logout</a>
  </header>

  <!-- Content -->
  <main class="dash-main">
    <section class="admin-card">
      <h2 class="admin-title">All Users</h2>

      <div class="table-wrap">
        <table class="admin-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Name</th>
              <th>Email</th>
              <th>Phone</th>
              <th>Role</th>
              <th>Created</th>
            </tr>
          </thead>
          <tbody>
            <?php foreach ($users as $u): ?>
              <tr>
                <td><?= (int)$u['id'] ?></td>
                <td><?= htmlspecialchars($u['full_name']) ?></td>
                <td><?= htmlspecialchars($u['email']) ?></td>
                <td><?= htmlspecialchars($u['phone']) ?></td>
                <td>
                  <span class="role-pill <?= $u['role'] === 'admin' ? 'role-admin' : 'role-user' ?>">
                    <?= htmlspecialchars($u['role']) ?>
                  </span>
                </td>
                <td><?= htmlspecialchars($u['created_at']) ?></td>
              </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      </div>
    </section>
  </main>
</body>
</html>
