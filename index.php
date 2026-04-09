<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';

check_session_timeout();


$search = mb_substr(trim($_GET['search'] ?? ''), 0, 100);
 
if ($search !== '') {
    $stmt = db()->prepare("
        SELECT * FROM books
        WHERE title LIKE ?
           OR author LIKE ?
           OR type LIKE ?
           OR isbn LIKE ?
        ORDER BY created_at DESC
    ");
 
    $like = "%$search%";
    $stmt->execute([$like, $like, $like, $like]);
} else {
    $stmt = db()->query("SELECT * FROM books ORDER BY created_at DESC");
}

$books = $stmt->fetchAll();

// Fetch reserved book IDs for catalog tags
$reservedStmt = db()->query("
    SELECT book_id, status
    FROM reservations
    WHERE status IN ('pending','approved')
");
$reservedBooks = [];

foreach ($reservedStmt->fetchAll() as $row) {
    $reservedBooks[$row['book_id']] = $row['status'];
}
?>

<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Book Catalog</title>
<link rel="stylesheet" href="<?= BASE_URL ?>/assets/styles.css">
</head>

<body class="dashboard">

<header class="dash-header">
  <div class="dash-brand">Book Catalog</div>

  <div class="nav-right">
    <?php if (!empty($_SESSION['user'])): ?>
      <a class="user-chip" href="<?= BASE_URL ?>/dashboard.php" title="View Profile">
        <?php if (!empty($_SESSION['user']['profile_photo'])): ?>
          <img class="user-avatar" src="<?= BASE_URL ?>/<?= htmlspecialchars($_SESSION['user']['profile_photo']) ?>" alt="Profile">
        <?php else: ?>
          <span class="user-initial">
            <?= strtoupper(substr($_SESSION['user']['full_name'], 0, 1)) ?>
          </span>
        <?php endif; ?>

        <span class="user-name">
          <?= htmlspecialchars($_SESSION['user']['full_name']) ?>
        </span>
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

  <form class="book-search" method="GET" action="index.php">
    <input
      type="text"
      name="search"
      placeholder="Search books, authors, type, or ISBN..."
      value="<?= htmlspecialchars($search) ?>"
    >

    <?php if ($search !== ''): ?>
      <a class="clear-search" style="margin-top: 10px;" href="index.php">Clear</a>
    <?php endif; ?>

    <button type="submit">Search</button>
  </form>

  <h1 class="admin-title" style="margin-top: 20px;">Available Books</h1>

  <?php if (!$books): ?>
    <?php if ($search !== ''): ?>
      <p>No results found for "<strong><?= htmlspecialchars($search) ?></strong>".</p>
    <?php else: ?>
      <p>No books available yet.</p>
    <?php endif; ?>
  <?php else: ?>

    <div class="book-grid">
      <?php foreach ($books as $book): ?>
        <a class="book-link" href="<?= BASE_URL ?>/book.php?id=<?= (int)$book['book_id'] ?>">
          <div class="book-card">

            <?php if (!empty($book['cover_image'])): ?>
              <img
                src="<?= BASE_URL ?>/<?= htmlspecialchars($book['cover_image']) ?>"
                class="book-cover"
                alt="Cover"
              >
            <?php endif; ?>

            <h3><?= htmlspecialchars($book['title']) ?></h3>

            <p class="book-author"><?= htmlspecialchars($book['author']) ?></p>

            <p class="book-isbn">
              ISBN: <?= htmlspecialchars($book['isbn'] ?? '—') ?>
            </p>

            <?php if (!empty($book['year_published'])): ?>
              <p class="book-year">
                Year Published: <?= htmlspecialchars((string)$book['year_published']) ?>
              </p>
            <?php endif; ?>

            <span class="book-type"><?= htmlspecialchars($book['type']) ?></span>

            <?php if (isset($reservedBooks[$book['book_id']])): ?>
              <?php $rStatus = $reservedBooks[$book['book_id']]; ?>
              <span class="book-reserved-tag <?= $rStatus === 'approved' ? 'tag-reserved' : 'tag-pending' ?>">
                <?= $rStatus === 'approved' ? 'Reserved' : 'Pending' ?>
              </span>
            <?php endif; ?>

            <p class="book-desc">
              <?= htmlspecialchars(mb_strimwidth($book['description'], 0, 120, '...')) ?>
            </p>

          </div>
        </a>
      <?php endforeach; ?>
    </div>

  <?php endif; ?>

</section>
</main>

</body>
</html>