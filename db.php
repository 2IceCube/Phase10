<?php
require_once __DIR__ . '/config.php';

function getDb(): PDO
{
    static $db = null;
    if ($db instanceof PDO) {
        return $db;
    }

    $needBootstrap = !file_exists(DB_PATH);
    $dir = dirname(DB_PATH);
    if (!is_dir($dir)) {
        mkdir($dir, 0775, true);
    }

    $db = new PDO('sqlite:' . DB_PATH);
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    initializeSchema($db, $needBootstrap);
    return $db;
}

function initializeSchema(PDO $db, bool $bootstrap): void
{
    $db->exec('PRAGMA foreign_keys = ON');

    $db->exec('CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        display_name TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ("admin", "player")),
        deposit_cents INTEGER NOT NULL DEFAULT 0,
        color TEXT NOT NULL DEFAULT "#1e88e5",
        guest_code TEXT DEFAULT NULL,
        guest_expires_at TEXT DEFAULT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )');

    $db->exec('CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )');

    $db->exec('CREATE TABLE IF NOT EXISTS phases (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        phase_number INTEGER NOT NULL UNIQUE,
        title TEXT NOT NULL,
        info TEXT NOT NULL DEFAULT ""
    )');

    $db->exec('CREATE TABLE IF NOT EXISTS scores (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        round_number INTEGER NOT NULL DEFAULT 1,
        points INTEGER NOT NULL DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )');

    $db->exec('CREATE TABLE IF NOT EXISTS user_phase_progress (
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        phase_number INTEGER NOT NULL,
        completed_at TEXT DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY(user_id, phase_number)
    )');

    if ($bootstrap) {
        seedInitialData($db);
    } else {
        ensureDefaults($db);
    }
}

function seedInitialData(PDO $db): void
{
    $stmt = $db->prepare('INSERT INTO users (username, display_name, password_hash, role) VALUES (:u, :d, :p, :r)');
    $stmt->execute([
        ':u' => DEFAULT_ADMIN_USER,
        ':d' => 'Administrator',
        ':p' => password_hash(DEFAULT_ADMIN_PASS, PASSWORD_DEFAULT),
        ':r' => 'admin',
    ]);

    $insertPhase = $db->prepare('INSERT INTO phases (phase_number, title, info) VALUES (:n, :t, "")');
    for ($i = 1; $i <= 10; $i++) {
        $insertPhase->execute([
            ':n' => $i,
            ':t' => 'Phase ' . $i,
        ]);
    }

    $stmtSetting = $db->prepare('INSERT INTO settings (key, value) VALUES (:k, :v)');
    $stmtSetting->execute([':k' => 'guest_code', ':v' => '1234']);
}

function ensureDefaults(PDO $db): void
{
    // ensure color column for existing installations
    $columns = $db->query('PRAGMA table_info(users)')->fetchAll();
    $hasColor = false;
    foreach ($columns as $col) {
        if (($col['name'] ?? '') === 'color') {
            $hasColor = true;
            break;
        }
    }
    if (!$hasColor) {
        $db->exec('ALTER TABLE users ADD COLUMN color TEXT NOT NULL DEFAULT "#1e88e5"');
    }

    $hasGuestCode = false;
    $hasGuestExpires = false;
    foreach ($columns as $col) {
        if (($col['name'] ?? '') === 'guest_code') {
            $hasGuestCode = true;
        }
        if (($col['name'] ?? '') === 'guest_expires_at') {
            $hasGuestExpires = true;
        }
    }
    if (!$hasGuestCode) {
        $db->exec('ALTER TABLE users ADD COLUMN guest_code TEXT DEFAULT NULL');
    }
    if (!$hasGuestExpires) {
        $db->exec('ALTER TABLE users ADD COLUMN guest_expires_at TEXT DEFAULT NULL');
    }

    $adminCount = (int)$db->query('SELECT COUNT(*) FROM users WHERE role = "admin"')->fetchColumn();
    if ($adminCount === 0) {
        $stmt = $db->prepare('INSERT INTO users (username, display_name, password_hash, role) VALUES (:u, :d, :p, :r)');
        $stmt->execute([
            ':u' => DEFAULT_ADMIN_USER,
            ':d' => 'Administrator',
            ':p' => password_hash(DEFAULT_ADMIN_PASS, PASSWORD_DEFAULT),
            ':r' => 'admin',
        ]);
    }

    $phaseCount = (int)$db->query('SELECT COUNT(*) FROM phases')->fetchColumn();
    if ($phaseCount < 10) {
        $existing = $db->query('SELECT phase_number FROM phases')->fetchAll(PDO::FETCH_COLUMN, 0);
        $missing = array_diff(range(1, 10), array_map('intval', $existing));
        $insertPhase = $db->prepare('INSERT INTO phases (phase_number, title, info) VALUES (:n, :t, "")');
        foreach ($missing as $num) {
            $insertPhase->execute([
                ':n' => $num,
                ':t' => 'Phase ' . $num,
            ]);
        }
    }

    $countStmt = $db->query('SELECT COUNT(*) FROM settings WHERE key = "guest_code"');
    if ((int)$countStmt->fetchColumn() === 0) {
        $stmtSetting = $db->prepare('INSERT INTO settings (key, value) VALUES (:k, :v)');
        $stmtSetting->execute([':k' => 'guest_code', ':v' => '1234']);
    }
}

function cleanupExpiredGuests(PDO $db): void
{
    $db->exec('DELETE FROM users WHERE guest_code IS NOT NULL AND guest_expires_at IS NOT NULL AND guest_expires_at <= datetime("now")');
}

function getSetting(PDO $db, string $key, ?string $default = null): ?string
{
    $stmt = $db->prepare('SELECT value FROM settings WHERE key = :k');
    $stmt->execute([':k' => $key]);
    $value = $stmt->fetchColumn();
    return $value !== false ? (string)$value : $default;
}

function setSetting(PDO $db, string $key, string $value): void
{
    $stmt = $db->prepare('REPLACE INTO settings (key, value) VALUES (:k, :v)');
    $stmt->execute([':k' => $key, ':v' => $value]);
}

function getUserPhaseProgress(PDO $db): array
{
    $progress = [];
    $rows = $db->query('SELECT id, display_name, deposit_cents, color FROM users ORDER BY display_name')->fetchAll();
    foreach ($rows as $row) {
        $progress[(int)$row['id']] = [
            'id' => (int)$row['id'],
            'display_name' => $row['display_name'],
            'deposit_cents' => (int)$row['deposit_cents'],
            'color' => $row['color'] ?: '#1e88e5',
            'completed' => [],
        ];
    }

    $done = $db->query('SELECT user_id, phase_number FROM user_phase_progress')->fetchAll();
    foreach ($done as $row) {
        $uid = (int)$row['user_id'];
        if (isset($progress[$uid])) {
            $progress[$uid]['completed'][] = (int)$row['phase_number'];
        }
    }

    return $progress;
}

function savePhaseProgress(PDO $db, int $userId, array $completed): void
{
    $db->beginTransaction();
    $stmtDelete = $db->prepare('DELETE FROM user_phase_progress WHERE user_id = :u');
    $stmtDelete->execute([':u' => $userId]);

    $stmtInsert = $db->prepare('INSERT INTO user_phase_progress (user_id, phase_number) VALUES (:u, :p)');
    foreach ($completed as $phaseNumber) {
        $num = (int)$phaseNumber;
        if ($num >= 1 && $num <= 10) {
            $stmtInsert->execute([':u' => $userId, ':p' => $num]);
        }
    }
    $db->commit();
}
