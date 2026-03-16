<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/security.php';
require_once __DIR__ . '/includes/reservations.php';
require_once __DIR__ . '/includes/logger.php';

$bookId = isset($_GET['id']) ? (int)$_GET['id'] : 0;

$stmt = db()->prepare("SELECT * FROM books WHERE book_id = ?");
$stmt->execute([$bookId]);
$book = $stmt->fetch();

if (!$book) {
    http_response_code(404);
    die("Book not found.");
}

mark_overdue_reservations();

$activeReservation = get_active_reservation_for_book($bookId);

$userId = (int)($_SESSION['user']['id'] ?? 0);
$userReservation = null;
if ($userId) {
    $stmt2 = db()->prepare("
        SELECT * FROM reservations
        WHERE user_id = ? AND book_id = ?
          AND status IN ('pending','approved')
        LIMIT 1
    ");
    $stmt2->execute([$userId, $bookId]);
    $userReservation = $stmt2->fetch() ?: null;
}

$flash = '';
$flashType = '';
$openReviewModal = false;

// ── POST handler ────────────────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    if (!validate_csrf_token()) {
        $flash = "Invalid request. Please refresh and try again.";
        $flashType = 'error';
    } elseif (!$userId) {
        header('Location: ' . BASE_URL . '/login.php');
        exit;
    } else {
        $action = $_POST['action'];

        // ── Reservation actions ──────────────────────────────────────────────
       if ($action === 'reserve') {
    // Re-check from DB at moment of insert
    $existing = get_active_reservation_for_book($bookId);

    if ($existing) {
        $flash     = "This book is already reserved or has a pending request.";
        $flashType = 'error';
    } elseif ($userReservation) {
        $flash     = "You already have a pending or active reservation for this book.";
        $flashType = 'error';
    } else {
        // Extra DB-level duplicate check
        $dupCheck = db()->prepare("
            SELECT id FROM reservations
            WHERE user_id = ? AND book_id = ?
              AND status IN ('pending', 'approved')
            LIMIT 1
        ");
        $dupCheck->execute([$userId, $bookId]);

        if ($dupCheck->fetch()) {
            $flash     = "You already have an active reservation for this book.";
            $flashType = 'error';
        } else {
            // ✅ Clean — insert the reservation
            $ins = db()->prepare("
                INSERT INTO reservations (user_id, book_id, status)
                VALUES (?, ?, 'pending')
            ");
            $ins->execute([$userId, $bookId]);

            log_transaction('INFO', 'Reservation requested', [
                'book_id' => $bookId,
                'user_id' => $userId,
            ]);

            $flash     = "Reservation request submitted! Awaiting admin approval.";
            $flashType = 'success';

            // Refresh state
            $activeReservation = get_active_reservation_for_book($bookId);
            $stmt2->execute([$userId, $bookId]);
            $userReservation = $stmt2->fetch() ?: null;
        }
    }

        } elseif ($action === 'cancel') {
            if ($userReservation && $userReservation['status'] === 'pending') {
                $upd = db()->prepare("UPDATE reservations SET status='cancelled' WHERE id=? AND user_id=?");
                $upd->execute([$userReservation['id'], $userId]);
                log_transaction('INFO', 'Reservation cancelled by user', ['book_id' => $bookId, 'user_id' => $_SESSION['user']['id']]);
                $flash = "Reservation request cancelled.";
                $flashType = 'success';
                $activeReservation = null;
                $userReservation = null;
            }

        // ── Review: submit ───────────────────────────────────────────────────
        } elseif ($action === 'submit_review') {
            $rating = max(1, min(5, (int)($_POST['rating'] ?? 5)));
            $body   = trim($_POST['review_body'] ?? '');

            if ($body === '') {
                $flash = "Review text cannot be empty.";
                $flashType = 'error';
                $openReviewModal = true;
            } elseif (mb_strlen($body) > 1000) {
                $flash = "Review must be 1000 characters or less.";
                $flashType = 'error';
                $openReviewModal = true;
            } else {
                // UPSERT: one review per user per book (delete old then insert)
                $del = db()->prepare("DELETE FROM reviews WHERE user_id=? AND book_id=?");
                $del->execute([$userId, $bookId]);
                $ins = db()->prepare("INSERT INTO reviews (user_id, book_id, rating, body) VALUES (?,?,?,?)");
                $ins->execute([$userId, $bookId, $rating, $body]);
                $flash = "Your review has been posted!";
                $flashType = 'success';
            }

        // ── Review: delete ───────────────────────────────────────────────────
        } elseif ($action === 'delete_review') {
            $revId = (int)($_POST['review_id'] ?? 0);
            if ($revId) {
                $del = db()->prepare("DELETE FROM reviews WHERE id=? AND user_id=?");
                $del->execute([$revId, $userId]);
                $flash = "Review deleted.";
                $flashType = 'success';
            }
        }
    }
}

// ── Load reviews ─────────────────────────────────────────────────────────────
$reviewStmt = db()->prepare("
    SELECT r.id, r.rating, r.body, r.created_at,
           u.full_name, u.profile_photo, u.id AS reviewer_id
    FROM reviews r
    JOIN users u ON u.id = r.user_id
    WHERE r.book_id = ?
    ORDER BY r.created_at DESC
");
$reviewStmt->execute([$bookId]);
$reviews = $reviewStmt->fetchAll();

// Check if current user already has a review
$myReview = null;
foreach ($reviews as $rv) {
    if ((int)$rv['reviewer_id'] === $userId) {
        $myReview = $rv;
        break;
    }
}

// Average rating
$avgRating = 0;
if (!empty($reviews)) {
    $avgRating = round(array_sum(array_column($reviews, 'rating')) / count($reviews), 1);
}

$isReservedByOther = $activeReservation && (int)($activeReservation['user_id'] ?? 0) !== $userId;
$isReservedByMe    = $userReservation !== null;
?>
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title><?= htmlspecialchars($book['title']) ?></title>
<link rel="stylesheet" href="<?= BASE_URL ?>/assets/styles.css">
<style>
/* ── Reserve button ── */
.btn-reserve{
  display:inline-block; padding:13px 28px;
  background:linear-gradient(135deg,#7c3aed,#6d28d9);
  color:#fff; border:none; border-radius:14px;
  font-size:15px; font-weight:700; cursor:pointer;
  text-decoration:none; margin-top:4px; transition:.15s ease; width:auto;
}
.btn-reserve:hover{ opacity:.9; transform:translateY(-1px); }

.reserve-status{
  display:flex; align-items:center; gap:12px; flex-wrap:wrap;
  padding:14px 18px; border-radius:14px; font-size:14px; margin-top:4px;
}
.pending-box  { background:#fef9c3; color:#713f12; border:1px solid #fde047; }
.approved-box { background:#dcfce7; color:#14532d; border:1px solid #86efac; }
.unavailable-box{ background:#f3f4f6; color:#374151; border:1px solid #d1d5db; }

.btn-cancel-small{
  padding:7px 14px; background:#ef4444; color:#fff; border:none;
  border-radius:8px; font-size:12px; font-weight:700; cursor:pointer; width:auto; margin:0;
}
.btn-cancel-small:hover{ opacity:.85; }
.overdue-badge{
  background:#fee2e2; color:#991b1b; padding:4px 10px; border-radius:999px;
  font-size:12px; font-weight:700;
}
.reserved-badge{
  position:absolute; top:10px; left:10px;
  background:rgba(0,0,0,0.75); color:#fff;
  padding:5px 12px; border-radius:999px; font-size:12px; font-weight:700;
  backdrop-filter:blur(4px);
}

/* ── Reviews section ── */
.reviews-section{
  margin-top:36px;
  border-top:1px solid #e5e7eb;
  padding-top:28px;
}
.reviews-heading{
  font-size:20px; font-weight:800; margin:0 0 4px;
}
.avg-stars{
  display:flex; align-items:center; gap:8px; margin-bottom:20px;
}
.stars-display{ font-size:20px; letter-spacing:2px; }
.avg-num{ font-size:14px; color:#6b7280; }

.btn-leave-review{
  display:inline-flex; align-items:center; gap:8px;
  padding:11px 22px;
  background:linear-gradient(135deg,#7c3aed,#6d28d9);
  color:#fff; border:none; border-radius:12px;
  font-size:14px; font-weight:700; cursor:pointer;
  text-decoration:none; transition:.15s ease; width:auto; margin:0 0 24px;
}
.btn-leave-review:hover{ opacity:.9; transform:translateY(-1px); }

/* ── Modal overlay ── */
.modal-overlay{
  display:none; position:fixed; inset:0;
  background:rgba(0,0,0,0.6); z-index:1000;
  align-items:center; justify-content:center;
  backdrop-filter:blur(3px);
}
.modal-overlay.open{ display:flex; }

.modal-box{
  background:#fff; border-radius:20px;
  padding:32px; width:100%; max-width:520px;
  box-shadow:0 24px 60px rgba(0,0,0,0.35);
  animation:modalIn .2s ease;
  margin:16px;
}
@keyframes modalIn{
  from{ opacity:0; transform:translateY(12px) scale(.97); }
  to  { opacity:1; transform:translateY(0) scale(1); }
}
.modal-title{ font-size:20px; font-weight:800; margin:0 0 20px; color:#111827; }
.modal-close{
  position:absolute; top:16px; right:20px;
  background:none; border:none; font-size:22px;
  cursor:pointer; color:#6b7280; width:auto; margin:0; padding:4px 8px;
  line-height:1;
}
.modal-close:hover{ color:#111; }

/* Star picker */
.star-picker{ display:flex; gap:6px; margin-bottom:18px; flex-direction:row-reverse; justify-content:flex-end; }
.star-picker input[type=radio]{ display:none; }
.star-picker label{
  font-size:32px; cursor:pointer;
  color:#d1d5db; transition:color .1s;
  user-select:none;
}
.star-picker input:checked ~ label,
.star-picker label:hover,
.star-picker label:hover ~ label{ color:#f59e0b; }

.review-textarea{
  width:100%; min-height:130px; resize:vertical;
  padding:12px 14px; border-radius:12px;
  border:1px solid #d1d5db; font-size:14px;
  font-family:inherit; outline:none; box-sizing:border-box;
  margin-bottom:6px;
}
.review-textarea:focus{ border-color:#7c3aed; box-shadow:0 0 0 3px rgba(124,58,237,.1); }
.char-count{ font-size:12px; color:#9ca3af; margin-bottom:16px; }

.btn-post-review{
  width:100%; padding:13px; background:linear-gradient(135deg,#7c3aed,#6d28d9);
  color:#fff; border:none; border-radius:12px;
  font-size:15px; font-weight:700; cursor:pointer; margin:0;
}
.btn-post-review:hover{ opacity:.9; }

/* ── Review cards ── */
.review-list{ display:flex; flex-direction:column; gap:16px; margin-top:8px; }
.review-card{
  background:#f8fafc; border:1px solid #e5e7eb;
  border-radius:16px; padding:18px 20px;
}
.review-card-header{
  display:flex; align-items:center; gap:12px; margin-bottom:10px;
}
.rev-avatar{
  width:44px; height:44px; border-radius:50%; object-fit:cover; flex-shrink:0;
}
.rev-avatar-fallback{
  width:44px; height:44px; border-radius:50%;
  background:#e5e7eb; display:flex; align-items:center;
  justify-content:center; font-weight:800; font-size:17px; color:#374151; flex-shrink:0;
}
.rev-meta{ flex:1; min-width:0; }
.rev-name{ font-weight:800; font-size:15px; }
.rev-stars{ font-size:16px; margin-top:2px; letter-spacing:1px; }
.rev-date{ font-size:12px; color:#9ca3af; margin-left:8px; }
.rev-body{ font-size:14px; line-height:1.65; color:#374151; }

.btn-delete-review{
  padding:6px 14px; background:#fee2e2; color:#991b1b;
  border:1px solid #fecaca; border-radius:8px;
  font-size:12px; font-weight:700; cursor:pointer;
  width:auto; margin:0; flex-shrink:0;
}
.btn-delete-review:hover{ background:#fecaca; }

.no-reviews{ color:#9ca3af; font-size:14px; margin-top:8px; }
</style>
</head>

<body class="dashboard">

<header class="dash-header">
  <a class="logout" href="<?= BASE_URL ?>/index.php">Back to Catalog</a>
  <div class="nav-right">
    <?php if (!empty($_SESSION['user'])): ?>
      <a class="user-chip" href="<?= BASE_URL ?>/dashboard.php">
        <?php if (!empty($_SESSION['user']['profile_photo'])): ?>
          <img class="user-avatar" src="<?= BASE_URL ?>/<?= htmlspecialchars($_SESSION['user']['profile_photo']) ?>" alt="Profile">
        <?php else: ?>
          <span class="user-initial"><?= strtoupper(substr($_SESSION['user']['full_name'],0,1)) ?></span>
        <?php endif; ?>
        <span class="user-name"><?= htmlspecialchars($_SESSION['user']['full_name']) ?></span>
      </a>
      <a class="logout" href="<?= BASE_URL ?>/logout.php">Logout</a>
    <?php else: ?>
      <a class="logout" href="<?= BASE_URL ?>/login.php">Login</a>
      <a class="logout" href="<?= BASE_URL ?>/registration.php">Register</a>
    <?php endif; ?>
  </div>
</header>

<main class="dash-main">
<section class="admin-card">

  <?php if ($flash): ?>
    <div class="alert <?= $flashType === 'success' ? 'success' : 'error' ?>" style="margin-bottom:18px;">
      <?= htmlspecialchars($flash) ?>
    </div>
  <?php endif; ?>

  <!-- ── Book Detail ───────────────────────────────────────────────────── -->
<div class="book-detail">
  <div style="position:relative; flex-shrink:0;">
    <?php if (!empty($book['cover_image'])): ?>
      <img class="book-detail-cover"
        src="<?= BASE_URL ?>/<?= htmlspecialchars($book['cover_image']) ?>"
        alt="Cover">
    <?php endif; ?>

    <?php if ($activeReservation): ?>
      <span class="reserved-badge">
        <?= $activeReservation['status'] === 'approved' ? 'Reserved' : 'Pending' ?>
      </span>
    <?php endif; ?>
  </div>

  <div class="book-detail-info">

    <h2 class="admin-title" style="margin-top:0;">
      <?= htmlspecialchars($book['title']) ?>
    </h2>

    <p class="book-author">
      <?= htmlspecialchars($book['author']) ?>
    </p>

    <?php if (!empty($book['isbn'])): ?>
      <p class="book-isbn">
        ISBN: <?= htmlspecialchars($book['isbn']) ?>
      </p>
    <?php endif; ?>

    <?php if (!empty($book['year_published'])): ?>
      <p class="book-year">
        Year Published: <?= htmlspecialchars((string)$book['year_published']) ?>
      </p>
    <?php endif; ?>

    <span class="book-type">
      <?= htmlspecialchars($book['type']) ?>
    </span>

    <hr style="margin:18px 0; opacity:0.2;">

    <p style="line-height:1.6; margin:0 0 24px;">
      <?= nl2br(htmlspecialchars($book['description'])) ?>
    </p>

      <!-- Reservation UI -->
      <?php if (!empty($_SESSION['user']) && $_SESSION['user']['role'] !== 'admin'): ?>
        <?php if ($isReservedByMe): ?>
          <?php if ($userReservation['status'] === 'pending'): ?>
            <div class="reserve-status pending-box">
              <span>Your reservation is <strong>pending admin approval</strong>.</span>
              <form method="post" style="display:inline; margin:0;">
                <?= csrf_field() ?>
                <input type="hidden" name="action" value="cancel">
                <button type="submit" class="btn-cancel-small" >Cancel Request</button>
              </form>
            </div>
          <?php elseif ($userReservation['status'] === 'approved'): ?>
            <div class="reserve-status approved-box">
              <strong>Approved!</strong> Return by:
              <strong><?= date('M d, Y', strtotime($userReservation['due_date'])) ?></strong>
              <?php if ($userReservation['is_overdue']): ?>
                <span class="overdue-badge">Overdue</span>
              <?php endif; ?>
            </div>
            <p style="font-size:13px; color:#6b7280; margin-top:8px;">
              Return this book from your <a href="<?= BASE_URL ?>/dashboard.php" style="color:#7c3aed;">profile page</a>.
            </p>
          <?php endif; ?>
        <?php elseif ($isReservedByOther): ?>
          <div class="reserve-status unavailable-box">
            🔒 This book is currently <strong>unavailable</strong> — reserved by another user.
          </div>
        <?php else: ?>
          <form method="post" style="margin:0;">
            <?= csrf_field() ?>
            <input type="hidden" name="action" value="reserve">
            <button type="submit" class="btn-reserve">Reserve this Book</button>
          </form>
        <?php endif; ?>
      <?php elseif (empty($_SESSION['user'])): ?>
        <a href="<?= BASE_URL ?>/login.php" class="btn-reserve" style="display:inline-block; text-align:center; text-decoration:none;">
          Login to Reserve
        </a>
      <?php endif; ?>
    </div>
  </div>

  <!-- ── Reviews Section ───────────────────────────────────────────────── -->
  <div class="reviews-section">
    <h3 class="reviews-heading">Reviews</h3>

    <!-- Average stars -->
    <?php if (!empty($reviews)): ?>
      <div class="avg-stars">
        <span class="stars-display">
          <?php for ($i = 1; $i <= 5; $i++): ?>
            <?= $i <= round($avgRating) ? '★' : '☆' ?>
          <?php endfor; ?>
        </span>
        <span class="avg-num"><?= $avgRating ?> / 5 &nbsp;·&nbsp; <?= count($reviews) ?> review<?= count($reviews) !== 1 ? 's' : '' ?></span>
      </div>
    <?php endif; ?>

    <!-- Leave / update review button -->
    <?php if (!empty($_SESSION['user']) && $_SESSION['user']['role'] !== 'admin'): ?>
      <button class="btn-leave-review" id="openReviewBtn">
        <?= $myReview ? 'Update My Review' : 'Leave a Review' ?>
      </button>
    <?php elseif (empty($_SESSION['user'])): ?>
      <p style="font-size:13px; color:#6b7280; margin-bottom:20px;">
        <a href="<?= BASE_URL ?>/login.php" style="color:#7c3aed;">Log in</a> to leave a review.
      </p>
    <?php endif; ?>

    <!-- Review list -->
    <?php if (empty($reviews)): ?>
      <p class="no-reviews">No reviews yet. Be the first to review this book!</p>
    <?php else: ?>
      <div class="review-list">
        <?php foreach ($reviews as $rv): ?>
          <div class="review-card">
            <div class="review-card-header">
              <?php if (!empty($rv['profile_photo'])): ?>
                <img class="rev-avatar" src="<?= BASE_URL ?>/<?= htmlspecialchars($rv['profile_photo']) ?>" alt="">
              <?php else: ?>
                <div class="rev-avatar-fallback"><?= strtoupper(substr($rv['full_name'], 0, 1)) ?></div>
              <?php endif; ?>

              <div class="rev-meta">
                <div class="rev-name">
                  <?= htmlspecialchars($rv['full_name']) ?>
                  <?php if ((int)$rv['reviewer_id'] === $userId): ?>
                    <span style="font-size:11px; color:#7c3aed; font-weight:600; margin-left:6px;">You</span>
                  <?php endif; ?>
                </div>
                <div class="rev-stars">
                  <?php for ($i = 1; $i <= 5; $i++): ?>
                    <span style="<?= $i <= $rv['rating'] ? 'opacity:1' : 'opacity:0.25' ?>">★</span>
                  <?php endfor; ?>
                  <span class="rev-date"><?= date('M d, Y', strtotime($rv['created_at'])) ?></span>
                </div>
              </div>

              <!-- Delete button (own review only) -->
              <?php if ((int)$rv['reviewer_id'] === $userId): ?>
                <form method="post" style="margin:0;">
                  <?= csrf_field() ?>
                  <input type="hidden" name="action" value="delete_review">
                  <input type="hidden" name="review_id" value="<?= (int)$rv['id'] ?>">
                  <button type="submit" class="btn-delete-review"
                    onclick="return confirm('Delete your review?')">Delete</button>
                </form>
              <?php endif; ?>
            </div>

            <p class="rev-body"><?= nl2br(htmlspecialchars($rv['body'])) ?></p>
          </div>
        <?php endforeach; ?>
      </div>
    <?php endif; ?>
  </div>

</section>
</main>

<!-- ── Review Modal ───────────────────────────────────────────────────────── -->
<?php if (!empty($_SESSION['user']) && $_SESSION['user']['role'] !== 'admin'): ?>
<div class="modal-overlay" id="reviewModal" style="position:fixed;">
  <div class="modal-box" style="position:relative;">
    <button class="modal-close" id="closeModal" type="button">✕</button>
    <h3 class="modal-title">
      <?= $myReview ? 'Update Your Review' : 'Leave a Review' ?>
    </h3>
    <p style="font-size:14px; color:#6b7280; margin:-12px 0 18px;">
      <strong><?= htmlspecialchars($book['title']) ?></strong>
    </p>

    <form method="post" id="reviewForm">
      <?= csrf_field() ?>
      <input type="hidden" name="action" value="submit_review">

      <!-- Star picker -->
      <label style="font-size:13px; color:#374151; font-weight:600; display:block; margin-bottom:8px;">Your Rating</label>
      <div class="star-picker" id="starPicker">
        <?php for ($i = 5; $i >= 1; $i--): ?>
          <input type="radio" name="rating" id="star<?= $i ?>" value="<?= $i ?>"
            <?= ($myReview && (int)$myReview['rating'] === $i) || (!$myReview && $i === 5) ? 'checked' : '' ?>>
          <label for="star<?= $i ?>" title="<?= $i ?> star<?= $i > 1 ? 's' : '' ?>">★</label>
        <?php endfor; ?>
      </div>

      <!-- Text -->
      <label style="font-size:13px; color:#374151; font-weight:600; display:block; margin-bottom:8px;">Your Review</label>
      <textarea
        class="review-textarea"
        name="review_body"
        id="reviewBody"
        placeholder="What did you think of this book?"
        maxlength="1000"
        required
      ><?= $myReview ? htmlspecialchars($myReview['body']) : '' ?></textarea>
      <div class="char-count"><span id="charCount"><?= $myReview ? mb_strlen($myReview['body']) : 0 ?></span> / 1000</div>

      <button type="submit" class="btn-post-review">
        <?= $myReview ? 'Update Review' : 'Post Review' ?>
      </button>
    </form>
  </div>
</div>
<?php endif; ?>

<script>
const modal   = document.getElementById('reviewModal');
const openBtn = document.getElementById('openReviewBtn');
const closeBtn= document.getElementById('closeModal');
const textarea= document.getElementById('reviewBody');
const charCount=document.getElementById('charCount');

if (openBtn) openBtn.addEventListener('click', () => modal.classList.add('open'));
if (closeBtn) closeBtn.addEventListener('click', () => modal.classList.remove('open'));
if (modal) modal.addEventListener('click', e => { if (e.target === modal) modal.classList.remove('open'); });

if (textarea && charCount) {
  textarea.addEventListener('input', () => {
    charCount.textContent = textarea.value.length;
  });
}

// Re-open modal if there was a validation error on submit
<?php if ($openReviewModal): ?>
  if (modal) modal.classList.add('open');
<?php endif; ?>
</script>

</body>
</html>