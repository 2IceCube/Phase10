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
        role TEXT NOT NULL CHECK(role IN ("admin", "player", "guest")),
        deposit_cents INTEGER NOT NULL DEFAULT 0,
        color TEXT NOT NULL DEFAULT "#1f6feb",
        guest_code TEXT DEFAULT NULL,
        guest_expires_at TEXT DEFAULT NULL,
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

    $db->exec('CREATE TABLE IF NOT EXISTS player_phases (
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        phase_number INTEGER NOT NULL,
        completed INTEGER NOT NULL DEFAULT 0,
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (user_id, phase_number)
    )');

    $db->exec('CREATE UNIQUE INDEX IF NOT EXISTS idx_users_guest_code ON users(guest_code)');

    migrateUsersTable($db);

    if ($bootstrap) {
        seedInitialData($db);
    } else {
        ensureDefaults($db);
    }

    ensurePlayerPhases($db);
}

function migrateUsersTable(PDO $db): void
{
    $schema = $db->query("SELECT sql FROM sqlite_master WHERE type='table' AND name='users'")->fetchColumn();
    if (!$schema) {
        return;
    }

    $needsGuestRole = strpos($schema, '"guest"') === false;
    $needsColor = strpos($schema, 'color') === false;
    $needsGuestCode = strpos($schema, 'guest_code') === false;
    $needsGuestExpires = strpos($schema, 'guest_expires_at') === false;

    if (!$needsGuestRole && !$needsColor && !$needsGuestCode && !$needsGuestExpires) {
        return;
    }

    $db->exec('CREATE TABLE IF NOT EXISTS users_new (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        display_name TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ("admin", "player", "guest")),
        deposit_cents INTEGER NOT NULL DEFAULT 0,
        color TEXT NOT NULL DEFAULT "#1f6feb",
        guest_code TEXT DEFAULT NULL,
        guest_expires_at TEXT DEFAULT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )');

    $columns = $db->query("PRAGMA table_info(users)")->fetchAll();
    $existing = array_column($columns, 'name');
    $selectParts = [
        'id',
        'username',
        'display_name',
        'password_hash',
        'role',
        'deposit_cents',
        'created_at',
    ];
    $selectList = implode(', ', array_intersect($selectParts, $existing));

    $rows = $db->query("SELECT {$selectList} FROM users")->fetchAll();
    $insert = $db->prepare('INSERT INTO users_new (id, username, display_name, password_hash, role, deposit_cents, color, guest_code, guest_expires_at, created_at)
        VALUES (:id, :username, :display_name, :password_hash, :role, :deposit_cents, :color, :guest_code, :guest_expires_at, :created_at)');

    foreach ($rows as $row) {
        $insert->execute([
            ':id' => $row['id'],
            ':username' => $row['username'],
            ':display_name' => $row['display_name'],
            ':password_hash' => $row['password_hash'],
            ':role' => $row['role'],
            ':deposit_cents' => $row['deposit_cents'],
            ':color' => $row['color'] ?? '#1f6feb',
            ':guest_code' => $row['guest_code'] ?? null,
            ':guest_expires_at' => $row['guest_expires_at'] ?? null,
            ':created_at' => $row['created_at'] ?? null,
        ]);
    }

    $db->exec('DROP TABLE users');
    $db->exec('ALTER TABLE users_new RENAME TO users');
}

function seedInitialData(PDO $db): void
{
    $stmt = $db->prepare('INSERT INTO users (username, display_name, password_hash, role, color) VALUES (:u, :d, :p, :r, :c)');
    $stmt->execute([
        ':u' => DEFAULT_ADMIN_USER,
        ':d' => 'Administrator',
        ':p' => password_hash(DEFAULT_ADMIN_PASS, PASSWORD_DEFAULT),
        ':r' => 'admin',
        ':c' => '#1f6feb',
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

function ensurePlayerPhases(PDO $db): void
{
    $users = $db->query('SELECT id FROM users WHERE role IN ("player", "guest")')->fetchAll();
    if (!$users) {
        return;
    }

    $insert = $db->prepare('INSERT OR IGNORE INTO player_phases (user_id, phase_number, completed) VALUES (:u, :p, 0)');
    foreach ($users as $user) {
        for ($i = 1; $i <= 10; $i++) {
            $insert->execute([
                ':u' => $user['id'],
                ':p' => $i,
            ]);
        }
    }
}
