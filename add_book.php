<?php
declare(strict_types=1);

require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/security.php';
require_once __DIR__ . '/includes/logger.php';

require_admin();

$errors = [];
$success = isset($_GET['success']);

$title = '';
$type = '';
$author = '';
$isbn = '';
$year_published = '';
$description = '';

function handle_book_cover_upload(array $file): ?string {
    global $ALLOWED_IMAGE_MIMES;

    if (($file['error'] ?? UPLOAD_ERR_NO_FILE) === UPLOAD_ERR_NO_FILE) {
        return null;
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
    $mime = $finfo->file($tmp);

    if (!in_array($mime, $ALLOWED_IMAGE_MIMES, true)) {
        throw new RuntimeException("Invalid image type. Only JPG/PNG allowed.");
    }

    $ext = match ($mime) {
        'image/jpeg' => 'jpg',
        'image/png'  => 'png',
        default      => 'bin',
    };

    $name = bin2hex(random_bytes(16)) . '.' . $ext;

    $destDir = __DIR__ . '/uploads/books';
    if (!is_dir($destDir)) {
        mkdir($destDir, 0755, true);
    }

    $dest = $destDir . '/' . $name;

    if (!move_uploaded_file($tmp, $dest)) {
        throw new RuntimeException("Failed to save image.");
    }

    return 'uploads/books/' . $name;
}

$allowedTypes = ['Graphic Novel', 'Fiction', 'Non-Fiction', 'Fantasy', 'Romance', 'Horror'];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validate_csrf_token()) {
        $errors[] = "Invalid request. Please refresh and try again.";
    } else {
        $title = trim($_POST['title'] ?? '');
        $type = trim($_POST['type'] ?? '');
        $author = trim($_POST['author'] ?? '');
        $isbn = trim($_POST['isbn'] ?? '');
        $year_published = trim($_POST['year_published'] ?? '');
        $description = trim($_POST['description'] ?? '');

        if ($title === '') $errors[] = "Title is required.";
        if ($author === '') $errors[] = "Author is required.";
        if ($isbn === '') $errors[] = "ISBN is required.";
        if ($year_published === '') $errors[] = "Year Published is required.";
        if ($description === '') $errors[] = "Description is required.";
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
                $coverPath = handle_book_cover_upload($_FILES['cover_image'] ?? []);

                $stmt = db()->prepare("
                    INSERT INTO books (title, type, author, isbn, year_published, description, cover_image)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ");
                $stmt->execute([
                    $title,
                    $type,
                    $author,
                    $isbn,
                    (int)$year_published,
                    $description,
                    $coverPath
                ]);

                log_admin('INFO', 'New book added', [
                    'title' => $title,
                    'author' => $author,
                    'isbn' => $isbn,
                    'year_published' => (int)$year_published
                ]);

                header("Location: add_book.php?success=1");
                exit;

            }  catch (Throwable $e) {
                log_admin('ERROR', 'Exception caught', [
                    'msg'   => $e->getMessage(),
                    'file'  => $e->getFile(),
                    'line'  => $e->getLine(),
                    'trace' => $e->getTraceAsString(),
                ]);

                $errors[] = DEBUG
                    ? ("Error: " . $e->getMessage())
                    : "Something went wrong. Please try again.";
            }
                        }
                    }
                }

?>
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Add Book</title>
<link rel="stylesheet" href="<?= BASE_URL ?>/assets/styles.css">
</head>

<body class="dashboard">

<header class="dash-header">
  <div class="dash-brand">Add Book</div>
  <div>
    <a class="logout" href="<?= BASE_URL ?>/admin.php">Back</a>
    <a class="logout" href="<?= BASE_URL ?>/logout.php">Logout</a>
  </div>
</header>

<main class="dash-main">
<section class="admin-card">

<h2 class="admin-title">Add a New Book</h2>

<?php if ($success): ?>
<div id="success-toast" class="toast-success">
  Book added successfully!
</div>
<?php endif; ?>

<?php if ($errors): ?>
  <div class="error-msg">
    <ul>
      <?php foreach ($errors as $err): ?>
        <li><?= htmlspecialchars($err) ?></li>
      <?php endforeach; ?>
    </ul>
  </div>
<?php endif; ?>

<form method="post" enctype="multipart/form-data">
  <?= csrf_field() ?>

  <label>Title</label>
  <input class="form-control" type="text" name="title" value="<?= htmlspecialchars($title) ?>" required>

  <label>Type</label>
  <select class="form-control" name="type" required>
    <option value="" disabled <?= $type === '' ? 'selected' : '' ?>>Select type</option>
    <?php foreach ($allowedTypes as $t): ?>
      <option value="<?= htmlspecialchars($t) ?>" <?= $type === $t ? 'selected' : '' ?>>
        <?= htmlspecialchars($t) ?>
      </option>
    <?php endforeach; ?>
  </select>

  <label>Author</label>
  <input class="form-control" type="text" name="author" value="<?= htmlspecialchars($author) ?>" required>

  <label>ISBN</label>
  <input
    class="form-control"
    type="text"
    name="isbn"
    inputmode="numeric"
    pattern="\d{10,13}"
    maxlength="13"
    value="<?= htmlspecialchars($isbn) ?>"
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
    value="<?= htmlspecialchars($year_published) ?>"
    required
  >

  <label>Description</label>
  <textarea class="form-control" name="description" rows="6" required><?= htmlspecialchars($description) ?></textarea>

  <label>Book Cover (JPG/PNG, max 2MB)</label>
  <input class="form-control" type="file" name="cover_image" accept=".jpg,.jpeg,.png,image/jpeg,image/png">

  <button type="submit" class="btn">Save Book</button>
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