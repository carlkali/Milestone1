<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/security.php';
require_once __DIR__ . '/includes/logger.php';

require_admin();

// Handle delete
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'delete_book') {
    if (!validate_csrf_token()) {
        header('Location: ' . BASE_URL . '/manage_books.php?error=csrf');
        exit;
    }

    $bookId = (int)($_POST['book_id'] ?? 0);
    if ($bookId) {
        // ✅ Check for active reservations before deleting
        $activeCheck = db()->prepare("
            SELECT COUNT(*) FROM reservations
            WHERE book_id = ? AND status IN ('pending', 'approved')
        ");
        $activeCheck->execute([$bookId]);
        $activeCount = (int)$activeCheck->fetchColumn();

        if ($activeCount > 0) {
            // Block delete — book is currently reserved
            header('Location: ' . BASE_URL . '/manage_books.php?error=reserved');
            exit;
        }

        $stmt = db()->prepare("SELECT * FROM books WHERE book_id = ?");
        $stmt->execute([$bookId]);
        $book = $stmt->fetch();

        if ($book) {
            if (!empty($book['cover_image'])) {
                $coverPath = __DIR__ . '/' . $book['cover_image'];
                if (file_exists($coverPath)) unlink($coverPath);
            }

            db()->prepare("DELETE FROM books WHERE book_id = ?")->execute([$bookId]);

            log_admin('WARNING', 'Book deleted', [
                'book_id' => $bookId,
                'title'   => $book['title'],
                'admin'   => $_SESSION['user']['email'],
            ]);
        }
    }

    header('Location: ' . BASE_URL . '/manage_books.php?deleted=1');
    exit;
}

$books   = db()->query("SELECT * FROM books ORDER BY created_at DESC")->fetchAll();
$deleted = isset($_GET['deleted']);
$error   = $_GET['error'] ?? '';

// ✅ Fetch all actively reserved book IDs
$activeRes = db()->query("
    SELECT DISTINCT book_id FROM reservations
    WHERE status IN ('pending', 'approved')
")->fetchAll(PDO::FETCH_COLUMN);
$activeReservedIds = array_flip($activeRes); // for fast isset() lookup
?>
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Manage Books</title>
  <link rel="stylesheet" href="<?= BASE_URL ?>/assets/styles.css">
  <style>
    .btn-edit {
      padding: 6px 14px;
      background: linear-gradient(135deg,#7c3aed,#6d28d9);
      color: #fff;
      border: none;
      border-radius: 8px;
      font-size: 12px;
      font-weight: 700;
      cursor: pointer;
      text-decoration: none;
      display: inline-block;
    }
    .btn-edit:hover { opacity: .85; }
    .btn-delete {
      padding: 6px 14px;
      background: #ef4444;
      color: #fff;
      border: none;
      border-radius: 8px;
      font-size: 12px;
      font-weight: 700;
      cursor: pointer;
    }
    .btn-delete:hover { opacity: .85; }
    .btn-delete:disabled {
      background: #d1d5db;
      color: #9ca3af;
      cursor: not-allowed;
      opacity: 1;
    }
    .book-thumb {
      width: 40px;
      height: 54px;
      object-fit: cover;
      border-radius: 6px;
    }
    .book-thumb-empty {
      width: 40px;
      height: 54px;
      background: #e5e7eb;
      border-radius: 6px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 18px;
    }
  </style>
</head>

<body class="dashboard">

<header class="dash-header">
  <div style="display:flex; align-items:center; gap:16px;">
    <div class="dash-brand">Manage Books</div>
    <a class="logout" href="<?= BASE_URL ?>/admin.php">← Back</a>
    <a class="logout" href="<?= BASE_URL ?>/add_book.php">+ Add Book</a>
  </div>
  <a class="logout" href="<?= BASE_URL ?>/logout.php">Logout</a>
</header>

<main class="dash-main">
  <section class="admin-card">
    <h2 class="admin-title">All Books</h2>

    <?php if ($deleted): ?>
      <div id="success-toast" class="toast-success">Book deleted successfully.</div>
    <?php endif; ?>

    <?php if ($error === 'reserved'): ?>
      <div class="alert error" style="margin-bottom:16px;">
        ❌ This book cannot be deleted — it has an active reservation.
      </div>
    <?php endif; ?>

    <div class="table-wrap">
      <table class="admin-table">
        <thead>
          <tr>
            <th>Cover</th>
            <th>Title</th>
            <th>Author</th>
            <th>Type</th>
            <th>Added</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          <?php if (empty($books)): ?>
            <tr>
              <td colspan="6" style="text-align:center; color:#9ca3af; padding:32px;">
                No books yet. <a href="<?= BASE_URL ?>/add_book.php" style="color:#7c3aed;">Add one →</a>
              </td>
            </tr>
          <?php else: ?>
            <?php foreach ($books as $b): ?>
              <?php $isReserved = isset($activeReservedIds[$b['book_id']]); ?>
              <tr>
                <td>
                  <?php if (!empty($b['cover_image'])): ?>
                    <img class="book-thumb"
                      src="<?= BASE_URL ?>/<?= htmlspecialchars($b['cover_image']) ?>"
                      alt="Cover">
                  <?php else: ?>
                    <div class="book-thumb-empty">📖</div>
                  <?php endif; ?>
                </td>
                <td><?= htmlspecialchars($b['title']) ?></td>
                <td><?= htmlspecialchars($b['author']) ?></td>
                <td><?= htmlspecialchars($b['type']) ?></td>
                <td><?= htmlspecialchars($b['created_at']) ?></td>
                <td>
                  <div style="display:flex; gap:8px; align-items:center;">

                    <a class="btn-edit"
                      href="<?= BASE_URL ?>/edit_book.php?id=<?= (int)$b['book_id'] ?>">
                      Edit
                    </a>

                    <form method="post" style="margin:0; padding:0; display:flex; align-items:center;"
                      onsubmit="return confirm('Delete \'<?= htmlspecialchars(addslashes($b['title'])) ?>\'? This cannot be undone.')">
                      <?= csrf_field() ?>
                      <input type="hidden" name="action" value="delete_book">
                      <input type="hidden" name="book_id" value="<?= (int)$b['book_id'] ?>">

                      <!-- ✅ Disabled if book is currently reserved -->
                      <button class="btn-delete" type="submit"
                        <?= $isReserved ? 'disabled title="Cannot delete — book is currently reserved"' : '' ?>>
                        Delete
                      </button>
                    </form>

                  </div>
                </td>
              </tr>
            <?php endforeach; ?>
          <?php endif; ?>
        </tbody>
      </table>
    </div>
  </section>
</main>

</body>
</html>

<script>
const toast = document.getElementById("success-toast");
if (toast) {
  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transform = "translateY(-10px)";
    setTimeout(() => toast.remove(), 300);
  }, 2000);
}
</script>