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
        color TEXT NOT NULL DEFAULT "#1f6feb",
        guest_code TEXT DEFAULT NULL,
        guest_expires_at TEXT DEFAULT NULL,
        deposit_cents INTEGER NOT NULL DEFAULT 0,
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
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        phase_number INTEGER NOT NULL,
        completed INTEGER NOT NULL DEFAULT 0,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, phase_number)
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
}

function ensureDefaults(PDO $db): void
{
    $adminCount = (int)$db->query('SELECT COUNT(*) FROM users WHERE role = "admin"')->fetchColumn();
    if ($adminCount === 0) {
        $stmt = $db->prepare('INSERT INTO users (username, display_name, password_hash, role, color) VALUES (:u, :d, :p, :r, :c)');
        $stmt->execute([
            ':u' => DEFAULT_ADMIN_USER,
            ':d' => 'Administrator',
            ':p' => password_hash(DEFAULT_ADMIN_PASS, PASSWORD_DEFAULT),
            ':r' => 'admin',
            ':c' => '#1f6feb',
        ]);
    }

    addColumnIfMissing($db, 'users', 'color', 'TEXT', '"#1f6feb"');
    addColumnIfMissing($db, 'users', 'guest_code', 'TEXT', 'NULL');
    addColumnIfMissing($db, 'users', 'guest_expires_at', 'TEXT', 'NULL');

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

function addColumnIfMissing(PDO $db, string $table, string $column, string $type, string $default): void
{
    $stmt = $db->prepare('PRAGMA table_info(' . $table . ')');
    $stmt->execute();
    $columns = array_column($stmt->fetchAll(), 'name');
    if (!in_array($column, $columns, true)) {
        $db->exec(sprintf('ALTER TABLE %s ADD COLUMN %s %s DEFAULT %s', $table, $column, $type, $default));
    }
}
