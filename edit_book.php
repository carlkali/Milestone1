<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/security.php';
require_once __DIR__ . '/includes/logger.php';

require_admin();

$bookId = (int)($_GET['id'] ?? 0);
if (!$bookId) {
    header('Location: ' . BASE_URL . '/admin.php');
    exit;
}

// Fetch existing book
$stmt = db()->prepare("SELECT * FROM books WHERE book_id = ?");
$stmt->execute([$bookId]);
$book = $stmt->fetch();

if (!$book) {
    header('Location: ' . BASE_URL . '/admin.php');
    exit;
}

$errors  = [];
$success = isset($_GET['success']);

$allowedTypes = ['Graphic Novel','Fiction','Non-Fiction','Fantasy','Romance','Horror'];

function handle_edit_cover_upload(array $file): ?string {
    global $ALLOWED_IMAGE_MIMES;

    if (($file['error'] ?? UPLOAD_ERR_NO_FILE) === UPLOAD_ERR_NO_FILE) {
        return null; // no new file — keep existing
    }

    if (($file['error'] ?? UPLOAD_ERR_OK) !== UPLOAD_ERR_OK) {
        throw new RuntimeException("File upload failed.");
    }

    if (($file['size'] ?? 0) > MAX_UPLOAD_BYTES) {
        throw new RuntimeException("Image too large (max 2MB).");
    }

    $tmp = $file['tmp_name'] ?? '';
    if ($tmp === '' || !is_uploaded_file($tmp)) {
        throw new RuntimeException("Invalid upload.");
    }

    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $mime  = $finfo->file($tmp);

    if (!in_array($mime, $ALLOWED_IMAGE_MIMES, true)) {
        throw new RuntimeException("Invalid image type. Only JPG/PNG allowed.");
    }

    $ext  = $mime === 'image/png' ? 'png' : 'jpg';
    $name = bin2hex(random_bytes(16)) . '.' . $ext;

    $destDir = __DIR__ . '/uploads/books';
    if (!is_dir($destDir)) mkdir($destDir, 0755, true);

    $dest = $destDir . '/' . $name;
    if (!move_uploaded_file($tmp, $dest)) {
        throw new RuntimeException("Failed to save image.");
    }

    return 'uploads/books/' . $name;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validate_csrf_token()) {
        $errors[] = "Invalid request. Please refresh and try again.";
    } else {
        $title          = trim($_POST['title'] ?? '');
        $author         = trim($_POST['author'] ?? '');
        $isbn           = trim($_POST['isbn'] ?? '');
        $type           = trim($_POST['type'] ?? '');
        $year_published = trim($_POST['year_published'] ?? '');
        $description    = trim($_POST['description'] ?? '');

        if ($title === '')                         $errors[] = "Title is required.";
        if ($author === '')                        $errors[] = "Author is required.";
        if ($isbn === '')                          $errors[] = "ISBN is required.";
        if ($year_published === '')                $errors[] = "Year Published is required.";
        if ($description === '')                   $errors[] = "Description is required.";
        if (!in_array($type, $allowedTypes, true)) $errors[] = "Invalid type selected.";

        if ($isbn !== '' && !preg_match('/^\d{10,13}$/', $isbn)) {
            $errors[] = "ISBN must be numeric and 10–13 digits.";
        }

        if ($year_published !== '') {
            if (!ctype_digit($year_published) || (int)$year_published < 1000 || (int)$year_published > (int)date('Y')) {
                $errors[] = "Invalid year published.";
            }
        }

        if (!$errors) {
            try {
                $newCover = handle_edit_cover_upload($_FILES['cover_image'] ?? []);

                if ($newCover !== null) {
                    // Delete old cover file if it exists
                    if (!empty($book['cover_image'])) {
                        $oldPath = __DIR__ . '/' . $book['cover_image'];
                        if (file_exists($oldPath)) unlink($oldPath);
                    }
                    $coverImage = $newCover;
                } else {
                    $coverImage = $book['cover_image']; // keep existing
                }

                $stmt = db()->prepare("
                    UPDATE books
                    SET title = ?, author = ?, isbn = ?, type = ?, year_published = ?, description = ?, cover_image = ?
                    WHERE book_id = ?
                ");
                $stmt->execute([
                    $title,
                    $author,
                    $isbn,
                    $type,
                    (int)$year_published,
                    $description,
                    $coverImage,
                    $bookId
                ]);

                log_admin('INFO', 'Book edited', [
                    'book_id'        => $bookId,
                    'title'          => $title,
                    'isbn'           => $isbn,
                    'year_published' => (int)$year_published,
                    'admin'          => $_SESSION['user']['email'],
                ]);

                header('Location: ' . BASE_URL . '/edit_book.php?id=' . $bookId . '&success=1');
                exit;

            } catch (Throwable $e) {
                $errors[] = $e->getMessage();
            }
        }
    }
}

// Refresh book after redirect
$stmt = db()->prepare("SELECT * FROM books WHERE book_id = ?");
$stmt->execute([$bookId]);
$book = $stmt->fetch();
?>
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Edit Book</title>
  <link rel="stylesheet" href="<?= BASE_URL ?>/assets/styles.css">
</head>
<body class="dashboard">

<header class="dash-header">
  <div style="display:flex; align-items:center; gap:16px;">
    <div class="dash-brand">Edit Book</div>
    <a class="logout" href="<?= BASE_URL ?>/admin.php">← Back</a>
  </div>
  <a class="logout" href="<?= BASE_URL ?>/logout.php">Logout</a>
</header>

<main class="dash-main">
<section class="admin-card">
  <h2 class="admin-title">Edit Book</h2>

  <?php if ($success): ?>
    <div id="success-toast" class="toast-success">Book updated successfully!</div>
  <?php endif; ?>

  <?php if ($errors): ?>
    <div class="error-msg">
      <ul><?php foreach ($errors as $e): ?><li><?= htmlspecialchars($e) ?></li><?php endforeach; ?></ul>
    </div>
  <?php endif; ?>

  <form method="post" enctype="multipart/form-data">
    <?= csrf_field() ?>

    <label>Title</label>
    <input class="form-control" type="text" name="title" maxlength="150"
      value="<?= htmlspecialchars($book['title']) ?>" required>

    <label>Type</label>
    <select class="form-control" name="type" required>
      <?php foreach ($allowedTypes as $t): ?>
        <option value="<?= htmlspecialchars($t) ?>" <?= $book['type'] === $t ? 'selected' : '' ?>>
          <?= htmlspecialchars($t) ?>
        </option>
      <?php endforeach; ?>
    </select>

    <label>Author</label>
    <input class="form-control" type="text" name="author" maxlength="120"
      value="<?= htmlspecialchars($book['author']) ?>" required>

    <label>ISBN</label>
    <input
      class="form-control"
      type="text"
      name="isbn"
      inputmode="numeric"
      pattern="\d{10,13}"
      maxlength="13"
      value="<?= htmlspecialchars((string)($book['isbn'] ?? '')) ?>"
      placeholder="Enter 10 to 13 digit ISBN"
      required
    >

    <label>Year Published</label>
    <input
      class="form-control"
      type="number"
      name="year_published"
      min="1000"
      max="<?= date('Y') ?>"
      value="<?= htmlspecialchars((string)($book['year_published'] ?? '')) ?>"
      required
    >

    <label>Description</label>
    <textarea class="form-control" name="description" rows="6" required
      style="resize:vertical;"><?= htmlspecialchars($book['description']) ?></textarea>

    <label>Cover Image <span style="color:#9ca3af;">(leave blank to keep current)</span></label>
    <?php if (!empty($book['cover_image'])): ?>
      <img src="<?= BASE_URL ?>/<?= htmlspecialchars($book['cover_image']) ?>"
        style="width:80px; border-radius:8px; margin-bottom:8px; display:block;" alt="Current cover">
    <?php endif; ?>
    <input class="form-control" type="file" name="cover_image" accept=".jpg,.jpeg,.png,image/jpeg,image/png">

    <button class="btn" type="submit">Save Changes</button>
  </form>
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