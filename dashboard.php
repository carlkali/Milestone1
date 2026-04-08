<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/security.php';
require_once __DIR__ . '/includes/reservations.php';

require_login();

mark_overdue_reservations();

$user = $_SESSION['user'];
$userId = (int)$user['id'];

$flash = '';
$flashType = '';

// Handle return book
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    if (!validate_csrf_token()) {
        $flash = "Invalid request.";
        $flashType = 'error';
    } else {
        $action = $_POST['action'];
        $resId = (int)($_POST['reservation_id'] ?? 0);

        if ($action === 'return' && $resId) {
            $stmt = db()->prepare("
                UPDATE reservations
                SET status = 'returned', returned_at = NOW()
                WHERE id = ? AND user_id = ? AND status = 'approved'
            ");
            $stmt->execute([$resId, $userId]);
            log_transaction('INFO', 'Book returned', [
            'user_id'        => $userId,
                  'reservation_id' => $resId,
            ]);
            $flash = "Book returned successfully. Thank you!";
            $flashType = 'success';
        } elseif ($action === 'cancel' && $resId) {
            $stmt = db()->prepare("
                UPDATE reservations
                SET status = 'cancelled'
                WHERE id = ? AND user_id = ? AND status = 'pending'
            ");
            $stmt->execute([$resId, $userId]);
            log_transaction('INFO', 'Reservation cancelled by user', [
            'user_id'        => $userId,
            'reservation_id' => $resId,
    ]);
            $flash = "Reservation request cancelled.";
            $flashType = 'success';
        }
    }
}

$reservations = get_user_reservations($userId);

// Separate into active and history
$activeReservations = array_filter($reservations, fn($r) => in_array($r['status'], ['pending','approved']));
$historyReservations = array_filter($reservations, fn($r) => in_array($r['status'], ['returned','cancelled','recalled']));
?>
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>My Profile</title>
  <link rel="stylesheet" href="<?= BASE_URL ?>/assets/styles.css">
  <style>
  .reservation-list{
    display:flex;
    flex-direction:column;
    gap:14px;
    margin-top:16px;
    text-align:left;
  }
  .res-card{
    display:flex;
    gap:16px;
    align-items:flex-start;
    background:#f8fafc;
    border:1px solid #e5e7eb;
    border-radius:14px;
    padding:14px 16px;
  }
  .res-cover{
    width:52px;
    height:72px;
    object-fit:cover;
    border-radius:8px;
    flex-shrink:0;
  }
  .res-cover-fallback{
    width:52px;
    height:72px;
    background:#e5e7eb;
    border-radius:8px;
    flex-shrink:0;
    display:flex;
    align-items:center;
    justify-content:center;
    font-size:22px;
  }
  .res-info{ flex:1; min-width:0; }
  .res-title{ font-weight:800; font-size:15px; margin-bottom:4px; }
  .res-author{ font-size:13px; color:#6b7280; margin-bottom:8px; }
  .res-meta{ font-size:12px; color:#6b7280; margin-bottom:10px; }
  .res-meta span{ margin-right:10px; }

  .status-pill{
    display:inline-block;
    padding:4px 12px;
    border-radius:999px;
    font-size:12px;
    font-weight:700;
  }
  .status-pending  { background:#fef9c3; color:#713f12; border:1px solid #fde047; }
  .status-approved { background:#dcfce7; color:#166534; border:1px solid #86efac; }
  .status-returned { background:#e0e7ff; color:#3730a3; border:1px solid #c7d2fe; }
  .status-cancelled{ background:#f3f4f6; color:#374151; border:1px solid #d1d5db; }
  .status-recalled { background:#fee2e2; color:#991b1b; border:1px solid #fecaca; }
  .status-overdue  { background:#fee2e2; color:#991b1b; border:1px solid #fecaca; }

  .btn-return{
    padding:8px 18px;
    background:linear-gradient(135deg,#7c3aed,#6d28d9);
    color:#fff;
    border:none;
    border-radius:10px;
    font-size:13px;
    font-weight:700;
    cursor:pointer;
    width:auto;
    margin:0;
  }
  .btn-return:hover{ opacity:.9; }
  .btn-cancel-res{
    padding:8px 18px;
    background:#ef4444;
    color:#fff;
    border:none;
    border-radius:10px;
    font-size:13px;
    font-weight:700;
    cursor:pointer;
    width:auto;
    margin:0;
  }
  .btn-cancel-res:hover{ opacity:.85; }

  .section-divider{
    border:none;
    border-top:1px solid #e5e7eb;
    margin:24px 0;
  }
  .section-label{
    font-size:13px;
    font-weight:700;
    color:#6b7280;
    text-transform:uppercase;
    letter-spacing:.5px;
    margin-bottom:10px;
  }
  .empty-state{
    text-align:center;
    padding:24px;
    color:#9ca3af;
    font-size:14px;
  }
  </style>
</head>
<body class="dashboard">

<header class="dash-header">
  <a class="logout" href="<?= BASE_URL ?>/index.php">Back to Catalog</a>
  <a class="logout" href="<?= BASE_URL ?>/logout.php">Logout</a>
</header>

<div style="display:flex; justify-content:center; padding:60px 20px 0; background:transparent;">

  <div style="width:100%; max-width:680px;">

    <!-- Profile Card -->
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

        <!-- Edit Profile button -->
        <div style="flex-shrink:0;">
          <a href="<?= BASE_URL ?>/edit_profile.php"
             style="display:inline-block; padding:10px 22px;
                    background:linear-gradient(135deg,#7c3aed,#6d28d9); color:#fff;
                    border-radius:10px; font-size:13px; font-weight:700;
                    text-decoration:none; white-space:nowrap;">
            Edit Profile
          </a>
        </div>

      </div>
    </div>

    <!-- Flash message -->
    <?php if ($flash): ?>
      <div class="alert <?= $flashType === 'success' ? 'success' : 'error' ?>" style="margin-bottom:16px;">
        <?= htmlspecialchars($flash) ?>
      </div>
    <?php endif; ?>

    <!-- Reservations Card -->
    <div class="admin-card" style="margin-bottom:40px;">
      <h2 class="admin-title">My Reservations</h2>

      <!-- Active -->
      <div class="section-label">Active</div>
      <?php if (empty($activeReservations)): ?>
        <div class="empty-state">No active reservations. <a href="<?= BASE_URL ?>/index.php" style="color:#7c3aed;">Browse books →</a></div>
      <?php else: ?>
        <div class="reservation-list">
          <?php foreach ($activeReservations as $res): ?>
            <div class="res-card">
              <?php if (!empty($res['cover_image'])): ?>
                <img class="res-cover" src="<?= BASE_URL ?>/<?= htmlspecialchars($res['cover_image']) ?>" alt="Cover">
              <?php else: ?>
                <div class="res-cover-fallback">📖</div>
              <?php endif; ?>

              <div class="res-info">
                <div class="res-title"><?= htmlspecialchars($res['title']) ?></div>
                <div class="res-author"><?= htmlspecialchars($res['author']) ?></div>

                <div class="res-meta">
                  <?php if ($res['status'] === 'approved' && $res['due_date']): ?>
                    <span>📅 Due: <strong><?= date('M d, Y', strtotime($res['due_date'])) ?></strong></span>
                  <?php endif; ?>
                  <span>Requested: <?= date('M d, Y', strtotime($res['requested_at'])) ?></span>
                </div>

                <div style="display:flex; align-items:center; gap:10px; flex-wrap:wrap;">
                  <?php if ($res['is_overdue'] && $res['status'] === 'approved'): ?>
                    <span class="status-pill status-overdue">⚠️ Overdue</span>
                  <?php else: ?>
                    <span class="status-pill status-<?= htmlspecialchars($res['status']) ?>">
                      <?= $res['status'] === 'pending' ? 'Pending Approval' : 'Approved' ?>
                    </span>
                  <?php endif; ?>

                  <?php if ($res['status'] === 'approved'): ?>
                    <form method="post" style="display:inline; margin:0;">
                      <?= csrf_field() ?>
                      <input type="hidden" name="action" value="return">
                      <input type="hidden" name="reservation_id" value="<?= (int)$res['id'] ?>">
                      <button type="submit" class="btn-return">Return Book</button>
                    </form>
                  <?php elseif ($res['status'] === 'pending'): ?>
                    <form method="post" style="display:inline; margin:0;">
                      <?= csrf_field() ?>
                      <input type="hidden" name="action" value="cancel">
                      <input type="hidden" name="reservation_id" value="<?= (int)$res['id'] ?>">
                      <button type="submit" class="btn-cancel-res">Cancel</button>
                    </form>
                  <?php endif; ?>
                </div>
              </div>
            </div>
          <?php endforeach; ?>
        </div>
      <?php endif; ?>

      <?php if (!empty($historyReservations)): ?>
        <hr class="section-divider">
        <div class="section-label">History</div>
        <div class="reservation-list">
          <?php foreach ($historyReservations as $res): ?>
            <div class="res-card" style="opacity:0.75;">
              <?php if (!empty($res['cover_image'])): ?>
                <img class="res-cover" src="<?= BASE_URL ?>/<?= htmlspecialchars($res['cover_image']) ?>" alt="Cover">
              <?php else: ?>
                <div class="res-cover-fallback">📖</div>
              <?php endif; ?>
              <div class="res-info">
                <div class="res-title"><?= htmlspecialchars($res['title']) ?></div>
                <div class="res-author"><?= htmlspecialchars($res['author']) ?></div>
                <div class="res-meta">
                  <span>Requested: <?= date('M d, Y', strtotime($res['requested_at'])) ?></span>
                  <?php if ($res['returned_at']): ?>
                    <span>Returned: <?= date('M d, Y', strtotime($res['returned_at'])) ?></span>
                  <?php endif; ?>
                </div>
                <span class="status-pill status-<?= htmlspecialchars($res['status']) ?>">
                  <?= match($res['status']) {
                    'returned'  => 'Returned',
                    'cancelled' => 'Cancelled',
                    'recalled'  => 'Recalled by Admin',
                    default     => ucfirst($res['status'])
                  } ?>
                </span>
              </div>
            </div>
          <?php endforeach; ?>
        </div>
      <?php endif; ?>

    </div>
  </div>
</div>

</body>
</html>