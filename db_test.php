<?php
require_once __DIR__ . '/includes/db.php';

try {
    $x = db()->query("SELECT DATABASE() AS dbname")->fetch();
    echo "DB CONNECTED: " . htmlspecialchars($x['dbname']);
} catch (Throwable $e) {
    echo "DB ERROR: " . htmlspecialchars($e->getMessage());
}
