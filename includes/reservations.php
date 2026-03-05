<?php
declare(strict_types=1);

require_once __DIR__ . '/db.php';

/**
 * Mark overdue reservations automatically.
 * Call this at the top of any page that displays reservation data.
 */
function mark_overdue_reservations(): void {
    db()->exec("
        UPDATE reservations
        SET is_overdue = 1
        WHERE status = 'approved'
          AND due_date IS NOT NULL
          AND due_date < NOW()
          AND is_overdue = 0
    ");
}

/**
 * Get the active reservation for a book (pending or approved only).
 */
function get_active_reservation_for_book(int $bookId): array|false {
    $stmt = db()->prepare("
        SELECT r.*, u.full_name, u.email
        FROM reservations r
        JOIN users u ON u.id = r.user_id
        WHERE r.book_id = ?
          AND r.status IN ('pending','approved')
        LIMIT 1
    ");
    $stmt->execute([$bookId]);
    return $stmt->fetch();
}

/**
 * Get all reservations for a specific user.
 */
function get_user_reservations(int $userId): array {
    $stmt = db()->prepare("
        SELECT r.*, b.title, b.author, b.type, b.cover_image
        FROM reservations r
        JOIN books b ON b.book_id = r.book_id
        WHERE r.user_id = ?
        ORDER BY r.requested_at DESC
    ");
    $stmt->execute([$userId]);
    return $stmt->fetchAll();
}

/**
 * Get all reservations (admin view).
 */
function get_all_reservations(?string $statusFilter = null): array {
    if ($statusFilter) {
        $stmt = db()->prepare("
            SELECT r.*, u.full_name, u.email, b.title AS book_title, b.author, b.cover_image
            FROM reservations r
            JOIN users u ON u.id = r.user_id
            JOIN books b ON b.book_id = r.book_id
            WHERE r.status = ?
            ORDER BY r.requested_at DESC
        ");
        $stmt->execute([$statusFilter]);
    } else {
        $stmt = db()->query("
            SELECT r.*, u.full_name, u.email, b.title AS book_title, b.author, b.cover_image
            FROM reservations r
            JOIN users u ON u.id = r.user_id
            JOIN books b ON b.book_id = r.book_id
            ORDER BY r.requested_at DESC
        ");
    }
    return $stmt->fetchAll();
}