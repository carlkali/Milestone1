<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/security.php';
require_once __DIR__ . '/includes/logger.php';

require_admin();

// Only allow POST requests
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: ' . BASE_URL . '/admin.php');
    exit;
}

if (!validate_csrf_token()) {
    header('Location: ' . BASE_URL . '/admin.php');
    exit;
}

$bookId = (int)($_POST['book_id'] ?? 0);
if (!$bookId) {
    header('Location: ' . BASE_URL . '/admin.php');
    exit;
}

// Fetch book first to get cover image path
$stmt = db()->prepare("SELECT * FROM books WHERE book_id = ?");
$stmt->execute([$bookId]);
$book = $stmt->fetch();

if (!$book) {
    header('Location: ' . BASE_URL . '/admin.php');
    exit;
}

// Delete cover image file if exists
if (!empty($book['cover_image'])) {
    $coverPath = __DIR__ . '/' . $book['cover_image'];
    if (file_exists($coverPath)) {
        unlink($coverPath);
    }
}

// Delete from database (reservations deleted automatically via CASCADE)
$stmt = db()->prepare("DELETE FROM books WHERE book_id = ?");
$stmt->execute([$bookId]);

log_admin('WARNING', 'Book deleted', [
    'book_id' => $bookId,
    'title'   => $book['title'],
    'admin'   => $_SESSION['user']['email'],
]);

header('Location: ' . BASE_URL . '/admin.php?deleted=1');
exit;