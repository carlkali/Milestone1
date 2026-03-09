<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/security.php';
require_once __DIR__ . '/includes/reservations.php';
require_once __DIR__ . '/includes/logger.php';

require_admin();

mark_overdue_reservations();

$flash     = '';
$flashType = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    if (!validate_csrf_token()) {
        $flash     = "Invalid request.";
        $flashType = 'error';
    } else {
        $action = $_POST['action'];
        $resId  = (int)($_POST['reservation_id'] ?? 0);

        if ($action === 'approve' && $resId) {
            $stmt = db()->prepare("
                UPDATE reservations
                SET status = 'approved',
                    approved_at = NOW(),
                    due_date = DATE_ADD(NOW(), INTERVAL 7 DAY)
                WHERE id = ? AND status = 'pending'
            ");
            $stmt->execute([$resId]);

            // ✅ Admin log only — no duplicate in transaction log
            log_admin('INFO', 'Reservation approved', [
                'reservation_id' => $resId,
                'approved_by'    => $_SESSION['user']['email'],
            ]);

            $flash     = "Reservation approved. Due date set to 7 days from now.";
            $flashType = 'success';

        } elseif ($action === 'reject' && $resId) {
            $stmt = db()->prepare("
                UPDATE reservations
                SET status = 'cancelled'
                WHERE id = ? AND status = 'pending'
            ");
            $stmt->execute([$resId]);

            // ✅ Admin log only
            log_admin('INFO', 'Reservation rejected', [
                'reservation_id' => $resId,
                'rejected_by'    => $_SESSION['user']['email'],
            ]);

            $flash     = "Reservation request rejected.";
            $flashType = 'success';

        } elseif ($action === 'recall' && $resId) {

            // ✅ Fetch book_id FIRST before using it
            $lookup = db()->prepare("SELECT book_id FROM reservations WHERE id = ?");
            $lookup->execute([$resId]);
            $bookId = (int)($lookup->fetchColumn() ?: 0);

            $stmt = db()->prepare("
                UPDATE reservations
                SET status = 'recalled', returned_at = NOW()
                WHERE id = ? AND status = 'approved'
            ");
            $stmt->execute([$resId]);

            // Cancel any pending reservations for the same book
            if ($bookId) {
                $stmt2 = db()->prepare("
                    UPDATE reservations
                    SET status = 'cancelled'
                    WHERE book_id = ?
                      AND status = 'pending'
                      AND id != ?
                ");
                $stmt2->execute([$bookId, $resId]);
            }

            // ✅ Admin log only
            log_admin('INFO', 'Reservation recalled', [
                'reservation_id' => $resId,
                'book_id'        => $bookId,
                'recalled_by'    => $_SESSION['user']['email'],
            ]);

            $flash     = "Book reservation recalled.";
            $flashType = 'success';
        }
    }
}

$statusFilter = $_GET['status'] ?? 'all';
$reservations = get_all_reservations($statusFilter === 'all' ? null : $statusFilter);

$countStmt = db()->query("SELECT status, COUNT(*) as cnt FROM reservations GROUP BY status");
$counts    = [];
foreach ($countStmt->fetchAll() as $row) {
    $counts[$row['status']] = (int)$row['cnt'];
}
$countAll = array_sum($counts);
?>
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Book Reservations — Admin</title>
<link rel="stylesheet" href="<?= BASE_URL ?>/assets/styles.css">
<style>
.tab-bar{
  display:flex;
  gap:8px;
  flex-wrap:wrap;
  margin-bottom:20px;
}
.tab{
  padding:8px 16px;
  border-radius:999px;
  font-size:13px;
  font-weight:600;
  text-decoration:none;
  border:1px solid #e5e7eb;
  color:#374151;
  background:#f9fafb;
  transition:.15s ease;
}
.tab:hover{ background:#f3f4f6; }
.tab.active{ background:#111827; color:#fff; border-color:#111827; }
.badge{
  display:inline-block;
  background:rgba(0,0,0,0.12);
  border-radius:999px;
  padding:1px 7px;
  font-size:11px;
  margin-left:4px;
}
.tab.active .badge{ background:rgba(255,255,255,0.2); }
.res-row td{ vertical-align:middle; white-space:normal !important; }
.res-thumb{ width:38px; height:52px; object-fit:cover; border-radius:6px; }
.res-thumb-ph{
  width:38px; height:52px; background:#e5e7eb;
  border-radius:6px; display:flex; align-items:center;
  justify-content:center; font-size:18px;
}
.status-pill{ display:inline-block; padding:4px 12px; border-radius:999px; font-size:12px; font-weight:700; }
.status-pending  { background:#fef9c3; color:#713f12; border:1px solid #fde047; }
.status-approved { background:#dcfce7; color:#166534; border:1px solid #86efac; }
.status-returned { background:#e0e7ff; color:#3730a3; border:1px solid #c7d2fe; }
.status-cancelled{ background:#f3f4f6; color:#374151; border:1px solid #d1d5db; }
.status-recalled { background:#fee2e2; color:#991b1b; border:1px solid #fecaca; }
.status-overdue  { background:#fee2e2; color:#991b1b; border:1px solid #fecaca; }
.btn-action{
  padding:7px 14px;
  border:none;
  border-radius:8px;
  font-size:12px;
  font-weight:700;
  cursor:pointer;
  width:auto;
  margin:0;
}
.btn-approve{ background:#16a34a; color:#fff; }
.btn-approve:hover{ background:#15803d; }
.btn-reject{ background:#ef4444; color:#fff; }
.btn-reject:hover{ background:#dc2626; }
.btn-recall{ background:#f97316; color:#fff; }
.btn-recall:hover{ background:#ea580c; }
.action-cell{ display:flex; gap:8px; flex-wrap:wrap; }
</style>
</head>

<body class="dashboard">

<header class="dash-header">
  <div style="display:flex; align-items:center; gap:16px;">
    <div class="dash-brand">Admin Panel</div>
    <a class="logout" href="<?= BASE_URL ?>/admin.php">Users</a>
    <a class="logout" href="<?= BASE_URL ?>/admin_reservations.php" style="background:rgba(255,255,255,0.12);">Reservations</a>
    <a class="logout" href="<?= BASE_URL ?>/add_book.php">Add Book</a>
  </div>
  <a class="logout" href="<?= BASE_URL ?>/logout.php">Logout</a>
</header>

<main class="dash-main">
<section class="admin-card">
  <h2 class="admin-title">Book Reservations</h2>

  <?php if ($flash): ?>
    <div class="alert <?= $flashType === 'success' ? 'success' : 'error' ?>" style="margin-bottom:16px;">
      <?= htmlspecialchars($flash) ?>
    </div>
  <?php endif; ?>

  <div class="tab-bar">
    <?php
    $tabs = [
      'all'       => 'All',
      'pending'   => 'Pending',
      'approved'  => 'Approved',
      'returned'  => 'Returned',
      'cancelled' => 'Cancelled',
      'recalled'  => 'Recalled',
    ];
    foreach ($tabs as $key => $label):
      $cnt      = $key === 'all' ? $countAll : ($counts[$key] ?? 0);
      $isActive = $statusFilter === $key;
    ?>
      <a class="tab <?= $isActive ? 'active' : '' ?>" href="?status=<?= $key ?>">
        <?= $label ?>
        <?php if ($cnt > 0): ?>
          <span class="badge"><?= $cnt ?></span>
        <?php endif; ?>
      </a>
    <?php endforeach; ?>
  </div>

  <?php if (empty($reservations)): ?>
    <div style="text-align:center; padding:40px; color:#9ca3af;">No reservations found.</div>
  <?php else: ?>
  <div class="table-wrap">
    <table class="admin-table">
      <thead>
        <tr>
          <th>#</th>
          <th>Book</th>
          <th>User</th>
          <th>Status</th>
          <th>Requested</th>
          <th>Due Date</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        <?php foreach ($reservations as $res): ?>
          <tr class="res-row">
            <td><?= (int)$res['id'] ?></td>
            <td>
              <div style="display:flex; align-items:center; gap:10px;">
                <?php if (!empty($res['cover_image'])): ?>
                  <img class="res-thumb" src="<?= BASE_URL ?>/<?= htmlspecialchars($res['cover_image']) ?>" alt="">
                <?php else: ?>
                  <div class="res-thumb-ph">📖</div>
                <?php endif; ?>
                <div>
                  <div style="font-weight:700; font-size:14px;"><?= htmlspecialchars($res['book_title']) ?></div>
                  <div style="font-size:12px; color:#6b7280;"><?= htmlspecialchars($res['author']) ?></div>
                </div>
              </div>
            </td>
            <td>
              <div style="font-weight:600; font-size:14px;"><?= htmlspecialchars($res['full_name']) ?></div>
              <div style="font-size:12px; color:#6b7280;"><?= htmlspecialchars($res['email']) ?></div>
            </td>
            <td>
              <?php if ($res['is_overdue'] && $res['status'] === 'approved'): ?>
                <span class="status-pill status-overdue">Overdue</span>
              <?php else: ?>
                <span class="status-pill status-<?= htmlspecialchars($res['status']) ?>">
                  <?= match($res['status']) {
                    'pending'   => 'Pending',
                    'approved'  => 'Approved',
                    'returned'  => 'Returned',
                    'cancelled' => 'Cancelled',
                    'recalled'  => 'Recalled',
                    default     => ucfirst($res['status'])
                  } ?>
                </span>
              <?php endif; ?>
            </td>
            <td style="font-size:13px;"><?= date('M d, Y', strtotime($res['requested_at'])) ?></td>
            <td style="font-size:13px;">
              <?= $res['due_date'] ? date('M d, Y', strtotime($res['due_date'])) : '—' ?>
            </td>
            <td>
              <div class="action-cell">
                <?php if ($res['status'] === 'pending'): ?>
                  <form method="post" style="margin:0;">
                    <?= csrf_field() ?>
                    <input type="hidden" name="action" value="approve">
                    <input type="hidden" name="reservation_id" value="<?= (int)$res['id'] ?>">
                    <button type="submit" class="btn-action btn-approve">Approve</button>
                  </form>
                  <form method="post" style="margin:0;">
                    <?= csrf_field() ?>
                    <input type="hidden" name="action" value="reject">
                    <input type="hidden" name="reservation_id" value="<?= (int)$res['id'] ?>">
                    <button type="submit" class="btn-action btn-reject">Reject</button>
                  </form>

                <?php elseif ($res['status'] === 'approved'): ?>
                  <form method="post" style="margin:0;">
                    <?= csrf_field() ?>
                    <input type="hidden" name="action" value="recall">
                    <input type="hidden" name="reservation_id" value="<?= (int)$res['id'] ?>">
                    <button type="submit" class="btn-action btn-recall">Recall</button>
                  </form>

                <?php else: ?>
                  <span style="font-size:12px; color:#9ca3af;">—</span>
                <?php endif; ?>
              </div>
            </td>
          </tr>
        <?php endforeach; ?>
      </tbody>
    </table>
  </div>
  <?php endif; ?>

</section>
</main>

</body>
</html>