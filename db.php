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
        color TEXT NOT NULL DEFAULT "#2f8bff",
        is_guest INTEGER NOT NULL DEFAULT 0,
        guest_code TEXT,
        guest_expires_at TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
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

    $db->exec('CREATE TABLE IF NOT EXISTS phase_progress (
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        phase_number INTEGER NOT NULL,
        completed INTEGER NOT NULL DEFAULT 0,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (user_id, phase_number)
    )');

    migrateUsersTable($db);

    if ($bootstrap) {
        seedInitialData($db);
    } else {
        ensureDefaults($db);
    }
}

function migrateUsersTable(PDO $db): void
{
    $columns = $db->query('PRAGMA table_info(users)')->fetchAll();
    $existing = array_column($columns, 'name');

    if (!in_array('color', $existing, true)) {
        $db->exec('ALTER TABLE users ADD COLUMN color TEXT NOT NULL DEFAULT "#2f8bff"');
    }
    if (!in_array('is_guest', $existing, true)) {
        $db->exec('ALTER TABLE users ADD COLUMN is_guest INTEGER NOT NULL DEFAULT 0');
    }
    if (!in_array('guest_code', $existing, true)) {
        $db->exec('ALTER TABLE users ADD COLUMN guest_code TEXT');
    }
    if (!in_array('guest_expires_at', $existing, true)) {
        $db->exec('ALTER TABLE users ADD COLUMN guest_expires_at TEXT');
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
}

function ensureDefaults(PDO $db): void
{
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
}
