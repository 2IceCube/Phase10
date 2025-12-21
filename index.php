<?php
require_once __DIR__ . '/db.php';

session_start();
$db = getDb();
$messages = [];
$errors = [];

function nowTimestamp(): string
{
    return (new DateTimeImmutable('now'))->format('Y-m-d H:i:s');
}

function purgeExpiredGuests(PDO $db): void
{
    $now = nowTimestamp();
    $stmt = $db->prepare('DELETE FROM users WHERE is_guest = 1 AND guest_expires_at IS NOT NULL AND guest_expires_at <= :now');
    $stmt->execute([':now' => $now]);
}

function isLoggedIn(): bool
{
    return isset($_SESSION['user']);
}

function currentUser(): ?array
{
    return $_SESSION['user'] ?? null;
}

function refreshUser(PDO $db): void
{
    if (!isLoggedIn()) {
        return;
    }
    $stmt = $db->prepare('SELECT id, username, display_name, role, deposit_cents, color, is_guest, guest_expires_at FROM users WHERE id = :id');
    $stmt->execute([':id' => $_SESSION['user']['id']]);
    if ($row = $stmt->fetch()) {
        $_SESSION['user'] = $row;
    } else {
        unset($_SESSION['user']);
    }
}

function requireLogin(): void
{
    if (!isLoggedIn()) {
        header('HTTP/1.1 403 Forbidden');
        echo 'Nicht angemeldet.';
        exit;
    }
}

function requireAdmin(): void
{
    if (!isLoggedIn() || $_SESSION['user']['role'] !== 'admin') {
        header('HTTP/1.1 403 Forbidden');
        echo 'Zugriff verweigert.';
        exit;
    }
}

function sumPoints(PDO $db, int $userId): int
{
    $stmt = $db->prepare('SELECT COALESCE(SUM(points), 0) FROM scores WHERE user_id = :id');
    $stmt->execute([':id' => $userId]);
    return (int)$stmt->fetchColumn();
}

function ensureProgressRecords(PDO $db, int $userId): void
{
    $existing = $db->prepare('SELECT phase_number FROM phase_progress WHERE user_id = :id');
    $existing->execute([':id' => $userId]);
    $have = array_map('intval', $existing->fetchAll(PDO::FETCH_COLUMN, 0));
    $missing = array_diff(range(1, 10), $have);
    if (!$missing) {
        return;
    }
    $insert = $db->prepare('INSERT INTO phase_progress (user_id, phase_number, completed) VALUES (:u, :p, 0)');
    foreach ($missing as $phase) {
        $insert->execute([':u' => $userId, ':p' => $phase]);
    }
}

function getBalances(PDO $db): array
{
    $stmt = $db->query('SELECT id, display_name, deposit_cents, color, is_guest, guest_expires_at FROM users ORDER BY display_name');
    $rows = $stmt->fetchAll();
    $result = [];
    foreach ($rows as $row) {
        $points = sumPoints($db, (int)$row['id']);
        $remaining = (int)$row['deposit_cents'] - $points;
        $result[] = [
            'id' => (int)$row['id'],
            'name' => $row['display_name'],
            'deposit' => (int)$row['deposit_cents'],
            'points' => $points,
            'remaining' => $remaining,
            'color' => $row['color'],
            'is_guest' => (int)$row['is_guest'],
            'guest_expires_at' => $row['guest_expires_at'],
        ];
    }

    usort($result, function ($a, $b) {
        return $b['remaining'] <=> $a['remaining'];
    });
    return $result;
}

function getPhases(PDO $db): array
{
    $stmt = $db->query('SELECT phase_number, title, info FROM phases ORDER BY phase_number');
    return $stmt->fetchAll();
}

function getScores(PDO $db, int $limit = 30): array
{
    $stmt = $db->prepare('SELECT s.id, s.round_number, s.points, s.created_at, u.display_name FROM scores s JOIN users u ON u.id = s.user_id ORDER BY s.round_number DESC, s.id DESC LIMIT :lim');
    $stmt->bindValue(':lim', $limit, PDO::PARAM_INT);
    $stmt->execute();
    return $stmt->fetchAll();
}

function getProgressForUsers(PDO $db, array $userIds): array
{
    if (!$userIds) {
        return [];
    }
    $placeholders = implode(',', array_fill(0, count($userIds), '?'));
    $stmt = $db->prepare("SELECT user_id, phase_number, completed FROM phase_progress WHERE user_id IN ($placeholders)");
    $stmt->execute($userIds);
    $result = [];
    foreach ($stmt->fetchAll() as $row) {
        $result[(int)$row['user_id']][(int)$row['phase_number']] = (int)$row['completed'];
    }
    return $result;
}

purgeExpiredGuests($db);
refreshUser($db);

if (isLoggedIn() && currentUser()['is_guest']) {
    $expires = currentUser()['guest_expires_at'];
    if ($expires && $expires <= nowTimestamp()) {
        unset($_SESSION['user']);
    }
}

if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: index.php');
    exit;
}

if (isset($_POST['action']) && $_POST['action'] === 'login') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $stmt = $db->prepare('SELECT id, username, display_name, password_hash, role, deposit_cents, color, is_guest, guest_expires_at FROM users WHERE username = :u AND is_guest = 0');
    $stmt->execute([':u' => $username]);
    if ($user = $stmt->fetch()) {
        if (password_verify($password, $user['password_hash'])) {
            $_SESSION['user'] = [
                'id' => $user['id'],
                'username' => $user['username'],
                'display_name' => $user['display_name'],
                'role' => $user['role'],
                'deposit_cents' => $user['deposit_cents'],
                'color' => $user['color'],
                'is_guest' => $user['is_guest'],
                'guest_expires_at' => $user['guest_expires_at'],
            ];
            ensureProgressRecords($db, (int)$user['id']);
            header('Location: index.php');
            exit;
        }
    }
    $errors[] = 'Anmeldung fehlgeschlagen. Bitte Zugangsdaten prüfen.';
}

if (isset($_POST['action']) && $_POST['action'] === 'guest_login') {
    $code = trim($_POST['guest_code'] ?? '');
    if (!preg_match('/^\d{4}$/', $code)) {
        $errors[] = 'Bitte einen 4-stelligen Gastcode eingeben.';
    } else {
        $stmt = $db->prepare('SELECT id, username, display_name, role, deposit_cents, color, is_guest, guest_expires_at FROM users WHERE is_guest = 1 AND guest_code = :c AND guest_expires_at > :now');
        $stmt->execute([':c' => $code, ':now' => nowTimestamp()]);
        if ($user = $stmt->fetch()) {
            $_SESSION['user'] = $user;
            ensureProgressRecords($db, (int)$user['id']);
            header('Location: index.php');
            exit;
        }
        $errors[] = 'Gastcode ungültig oder abgelaufen.';
    }
}

if (isset($_POST['action']) && $_POST['action'] === 'create_user') {
    requireAdmin();
    $username = trim($_POST['username'] ?? '');
    $display = trim($_POST['display_name'] ?? '');
    $password = $_POST['password'] ?? '';
    $role = $_POST['role'] === 'admin' ? 'admin' : 'player';
    $color = trim($_POST['color'] ?? '') ?: '#2f8bff';
    if ($username && $display && $password) {
        $stmt = $db->prepare('INSERT INTO users (username, display_name, password_hash, role, color) VALUES (:u, :d, :p, :r, :c)');
        try {
            $stmt->execute([
                ':u' => $username,
                ':d' => $display,
                ':p' => password_hash($password, PASSWORD_DEFAULT),
                ':r' => $role,
                ':c' => $color,
            ]);
            ensureProgressRecords($db, (int)$db->lastInsertId());
            $messages[] = 'Nutzer wurde angelegt.';
        } catch (PDOException $e) {
            $errors[] = 'Fehler beim Anlegen: ' . htmlspecialchars($e->getMessage());
        }
    } else {
        $errors[] = 'Bitte alle Felder ausfüllen (Nutzername, Anzeigename, Passwort).';
    }
}

if (isset($_POST['action']) && $_POST['action'] === 'create_guest') {
    requireAdmin();
    $display = trim($_POST['display_name'] ?? '');
    $deposit = (int)round((float)($_POST['deposit_euro'] ?? 0) * 100);
    $color = trim($_POST['color'] ?? '') ?: '#2f8bff';
    $code = trim($_POST['guest_code'] ?? '');
    if (!$display || !preg_match('/^\d{4}$/', $code)) {
        $errors[] = 'Bitte Name und 4-stelligen Code angeben.';
    } else {
        $exists = $db->prepare('SELECT COUNT(*) FROM users WHERE guest_code = :c AND is_guest = 1');
        $exists->execute([':c' => $code]);
        if ($exists->fetchColumn() > 0) {
            $errors[] = 'Gastcode ist bereits vergeben.';
        } else {
            $username = 'guest_' . strtolower(preg_replace('/\s+/', '', $display)) . '_' . $code;
            $stmt = $db->prepare('INSERT INTO users (username, display_name, password_hash, role, deposit_cents, color, is_guest, guest_code, guest_expires_at) VALUES (:u, :d, :p, "player", :dep, :c, 1, :code, :exp)');
            $expires = (new DateTimeImmutable('+24 hours'))->format('Y-m-d H:i:s');
            $stmt->execute([
                ':u' => $username,
                ':d' => $display,
                ':p' => password_hash(bin2hex(random_bytes(16)), PASSWORD_DEFAULT),
                ':dep' => $deposit,
                ':c' => $color,
                ':code' => $code,
                ':exp' => $expires,
            ]);
            ensureProgressRecords($db, (int)$db->lastInsertId());
            $messages[] = 'Gastaccount erstellt (gültig bis ' . $expires . ').';
        }
    }
}

if (isset($_POST['action']) && $_POST['action'] === 'update_deposit') {
    requireAdmin();
    $userId = (int)($_POST['user_id'] ?? 0);
    $deposit = (int)round((float)($_POST['deposit_euro'] ?? 0) * 100);
    $stmt = $db->prepare('UPDATE users SET deposit_cents = :d WHERE id = :id');
    $stmt->execute([':d' => $deposit, ':id' => $userId]);
    $messages[] = 'Einzahlung aktualisiert.';
    refreshUser($db);
}

if (isset($_POST['action']) && $_POST['action'] === 'rename_user') {
    requireAdmin();
    $userId = (int)($_POST['user_id'] ?? 0);
    $display = trim($_POST['display_name'] ?? '');
    if ($display) {
        $stmt = $db->prepare('UPDATE users SET display_name = :n WHERE id = :id');
        $stmt->execute([':n' => $display, ':id' => $userId]);
        $messages[] = 'Name geändert.';
        refreshUser($db);
    }
}

if (isset($_POST['action']) && $_POST['action'] === 'update_color') {
    requireAdmin();
    $userId = (int)($_POST['user_id'] ?? 0);
    $color = trim($_POST['color'] ?? '') ?: '#2f8bff';
    $stmt = $db->prepare('UPDATE users SET color = :c WHERE id = :id');
    $stmt->execute([':c' => $color, ':id' => $userId]);
    $messages[] = 'Farbe aktualisiert.';
}

if (isset($_POST['action']) && $_POST['action'] === 'update_password') {
    requireAdmin();
    $userId = (int)($_POST['user_id'] ?? 0);
    $password = $_POST['password'] ?? '';
    if (strlen($password) < 4) {
        $errors[] = 'Passwort muss mindestens 4 Zeichen haben.';
    } else {
        $stmt = $db->prepare('UPDATE users SET password_hash = :p WHERE id = :id');
        $stmt->execute([':p' => password_hash($password, PASSWORD_DEFAULT), ':id' => $userId]);
        $messages[] = 'Passwort aktualisiert.';
    }
}

if (isset($_POST['action']) && $_POST['action'] === 'add_score') {
    requireAdmin();
    $userId = (int)($_POST['user_id'] ?? 0);
    $points = (int)($_POST['points'] ?? 0);
    $round = (int)($_POST['round_number'] ?? 1);
    if ($userId && $round >= 1) {
        $stmt = $db->prepare('INSERT INTO scores (user_id, round_number, points) VALUES (:u, :r, :p)');
        $stmt->execute([':u' => $userId, ':r' => $round, ':p' => $points]);
        $messages[] = 'Punkte eingetragen.';
    }
}

if (isset($_POST['action']) && $_POST['action'] === 'update_score') {
    requireAdmin();
    $scoreId = (int)($_POST['score_id'] ?? 0);
    $points = (int)($_POST['points'] ?? 0);
    $round = (int)($_POST['round_number'] ?? 1);
    if ($scoreId) {
        $stmt = $db->prepare('UPDATE scores SET points = :p, round_number = :r WHERE id = :id');
        $stmt->execute([':p' => $points, ':r' => $round, ':id' => $scoreId]);
        $messages[] = 'Punkte geändert.';
    }
}

if (isset($_POST['action']) && $_POST['action'] === 'delete_score') {
    requireAdmin();
    $scoreId = (int)($_POST['score_id'] ?? 0);
    $stmt = $db->prepare('DELETE FROM scores WHERE id = :id');
    $stmt->execute([':id' => $scoreId]);
    $messages[] = 'Eintrag gelöscht.';
}

if (isset($_POST['action']) && $_POST['action'] === 'update_phase') {
    requireAdmin();
    $number = (int)($_POST['phase_number'] ?? 0);
    $title = trim($_POST['title'] ?? '');
    $info = trim($_POST['info'] ?? '');
    if ($number >= 1 && $number <= 10 && $title) {
        $stmt = $db->prepare('UPDATE phases SET title = :t, info = :i WHERE phase_number = :n');
        $stmt->execute([':t' => $title, ':i' => $info, ':n' => $number]);
        $messages[] = 'Phase aktualisiert.';
    } else {
        $errors[] = 'Bitte Titel angeben (1-10).';
    }
}

if (isset($_POST['action']) && in_array($_POST['action'], ['toggle_phase', 'set_phase'], true)) {
    requireLogin();
    $userId = (int)($_POST['user_id'] ?? 0);
    $phase = (int)($_POST['phase_number'] ?? 0);
    if ($phase < 1 || $phase > 10) {
        header('Content-Type: application/json');
        echo json_encode(['ok' => false, 'error' => 'Ungültige Phase.']);
        exit;
    }
    $actor = currentUser();
    if ($actor['role'] !== 'admin' && $actor['id'] !== $userId) {
        header('Content-Type: application/json');
        echo json_encode(['ok' => false, 'error' => 'Keine Berechtigung.']);
        exit;
    }
    ensureProgressRecords($db, $userId);
    $completed = isset($_POST['completed']) ? (int)$_POST['completed'] : null;
    if ($completed === null) {
        $stmt = $db->prepare('UPDATE phase_progress SET completed = CASE completed WHEN 1 THEN 0 ELSE 1 END, updated_at = :u WHERE user_id = :uid AND phase_number = :p');
        $stmt->execute([':u' => nowTimestamp(), ':uid' => $userId, ':p' => $phase]);
    } else {
        $stmt = $db->prepare('UPDATE phase_progress SET completed = :c, updated_at = :u WHERE user_id = :uid AND phase_number = :p');
        $stmt->execute([':c' => $completed, ':u' => nowTimestamp(), ':uid' => $userId, ':p' => $phase]);
    }
    header('Content-Type: application/json');
    echo json_encode(['ok' => true]);
    exit;
}

if (isset($_GET['ajax']) && $_GET['ajax'] === 'state') {
    requireLogin();
    $isAdmin = currentUser()['role'] === 'admin';
    $balances = getBalances($db);
    $phases = getPhases($db);
    $visibleUsers = $isAdmin ? array_column($balances, 'id') : [currentUser()['id']];
    $progress = getProgressForUsers($db, $visibleUsers);
    $scores = $isAdmin ? getScores($db) : [];
    header('Content-Type: application/json');
    echo json_encode([
        'ok' => true,
        'timestamp' => nowTimestamp(),
        'balances' => $balances,
        'phases' => $phases,
        'progress' => $progress,
        'scores' => $scores,
        'isAdmin' => $isAdmin,
        'currentUserId' => currentUser()['id'],
    ]);
    exit;
}

refreshUser($db);

$isAdmin = isLoggedIn() && currentUser()['role'] === 'admin';
$balances = isLoggedIn() ? getBalances($db) : [];
$phases = isLoggedIn() ? getPhases($db) : [];
$scores = $isAdmin ? getScores($db) : [];
$visibleUsers = $isAdmin ? $balances : array_filter($balances, function ($row) {
    return isLoggedIn() && $row['id'] === currentUser()['id'];
});

if (isLoggedIn()) {
    $userIds = array_map(fn($row) => (int)$row['id'], $visibleUsers);
    foreach ($userIds as $id) {
        ensureProgressRecords($db, $id);
    }
    $progress = getProgressForUsers($db, $userIds);
} else {
    $progress = [];
}

$currentWinner = $balances[0] ?? null;
?>
<!doctype html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Phase 10 Mobile</title>
    <style>
        :root {
            color-scheme: light;
            --bg: #f5f6f8;
            --card: #ffffff;
            --accent: #1b7f69;
            --muted: #8c98a4;
            --shadow: 0 8px 24px rgba(0,0,0,0.08);
        }
        * { box-sizing: border-box; }
        body {
            font-family: "Segoe UI", system-ui, -apple-system, sans-serif;
            margin: 0;
            background: var(--bg);
            color: #1d1d1f;
        }
        header {
            position: sticky;
            top: 0;
            z-index: 10;
            padding: 1rem 1.25rem;
            background: #0b5f4d;
            color: #fff;
        }
        header h1 {
            font-size: 1.2rem;
            margin: 0;
        }
        header .subtitle {
            font-size: 0.85rem;
            opacity: 0.85;
            margin-top: 0.25rem;
        }
        header .user {
            margin-top: 0.5rem;
            font-size: 0.85rem;
        }
        main {
            padding: 1rem 1rem 5.5rem;
        }
        .pill {
            display: inline-flex;
            align-items: center;
            gap: 0.4rem;
            padding: 0.3rem 0.6rem;
            background: rgba(255,255,255,0.18);
            border-radius: 999px;
            font-size: 0.75rem;
        }
        .status {
            background: rgba(255,255,255,0.16);
            padding: 0.25rem 0.6rem;
            border-radius: 999px;
            font-size: 0.7rem;
            display: inline-flex;
            align-items: center;
            gap: 0.3rem;
        }
        .section {
            background: var(--card);
            border-radius: 16px;
            box-shadow: var(--shadow);
            padding: 1rem;
            margin-bottom: 1rem;
        }
        .section h2 { margin: 0 0 0.75rem; font-size: 1rem; }
        .message { color: #0b6e4f; margin-bottom: 0.5rem; }
        .error { color: #b3261e; margin-bottom: 0.5rem; }
        .tabs {
            position: fixed;
            bottom: 0;
            left: 0;
            right: 0;
            background: #fff;
            border-top: 1px solid #e0e0e0;
            display: flex;
            justify-content: space-around;
            padding: 0.5rem 0.25rem 0.75rem;
            z-index: 10;
        }
        .tabs button {
            background: none;
            border: none;
            font-size: 0.85rem;
            color: var(--muted);
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 0.35rem;
        }
        .tabs button.active { color: var(--accent); font-weight: 600; }
        .view { display: none; }
        .view.active { display: block; }
        .leaderboard {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
        }
        .leaderboard th, .leaderboard td { padding: 0.45rem 0.3rem; text-align: left; }
        .leaderboard th { color: var(--muted); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; }
        .leaderboard tr + tr td { border-top: 1px solid #eef0f2; }
        .phases-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 0.75rem;
        }
        .phase-card {
            background: #f5f7f9;
            border-radius: 12px;
            padding: 0.75rem;
            min-height: 90px;
        }
        .phase-card h4 { margin: 0 0 0.3rem; font-size: 0.9rem; }
        .phase-card p { margin: 0; font-size: 0.8rem; color: var(--muted); }
        .card-stack {
            display: grid;
            gap: 1.25rem;
        }
        .player-card {
            background: #fefdf8;
            border-radius: 20px;
            box-shadow: var(--shadow);
            padding: 1rem;
            min-height: 70vh;
            display: flex;
            flex-direction: column;
            border: 3px solid transparent;
        }
        .player-card .header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 0.75rem;
        }
        .player-card .name {
            font-size: 1.2rem;
            font-weight: 700;
        }
        .player-card .chip {
            padding: 0.3rem 0.6rem;
            border-radius: 999px;
            font-size: 0.75rem;
            background: #fff;
            border: 1px solid #e2e6ea;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 0.5rem;
            margin-bottom: 1rem;
        }
        .stat {
            background: #fff;
            border-radius: 12px;
            padding: 0.6rem;
            text-align: center;
            border: 1px solid #e8ecf0;
        }
        .stat strong { display: block; font-size: 1rem; }
        .phase-grid-card {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 0.5rem;
        }
        .phase-toggle {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0.6rem;
            border-radius: 12px;
            background: #fff;
            border: 1px solid #e5e8ec;
            font-size: 0.85rem;
        }
        .phase-toggle input {
            width: 22px;
            height: 22px;
        }
        form label { display: block; font-size: 0.85rem; margin-bottom: 0.35rem; }
        input, select, textarea, button {
            width: 100%;
            padding: 0.65rem 0.75rem;
            border-radius: 12px;
            border: 1px solid #d9dee3;
            font-size: 0.95rem;
        }
        button {
            background: var(--accent);
            color: #fff;
            border: none;
            font-weight: 600;
            margin-top: 0.5rem;
        }
        .btn-secondary {
            background: #fff;
            color: #0b5f4d;
            border: 1px solid #c5d9d4;
        }
        .form-grid {
            display: grid;
            gap: 0.9rem;
        }
        .score-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85rem;
        }
        .score-table th, .score-table td { padding: 0.4rem; border-bottom: 1px solid #eef0f2; }
        .score-actions { display: flex; flex-wrap: wrap; gap: 0.4rem; }
        .score-actions input { width: 80px; }
        .danger {
            background: #fbe9e7;
            color: #b3261e;
            border: 1px solid #f5c2bc;
        }
        @media (min-width: 800px) {
            main { padding: 2rem 2rem 6rem; }
            .card-stack { grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); }
        }
    </style>
</head>
<body>
<header>
    <h1>Phase 10 Live</h1>
    <div class="subtitle">Mobile-First Übersicht & Karten</div>
    <div class="user">
        <?php if ($currentWinner): ?>
            <span class="pill">Aktueller Gewinner: <strong><?php echo htmlspecialchars($currentWinner['name']); ?></strong> (<?php echo number_format($currentWinner['remaining'] / 100, 2, ',', '.'); ?> €)</span>
        <?php endif; ?>
    </div>
    <div class="user">
        <?php if (isLoggedIn()): ?>
            Angemeldet als <strong><?php echo htmlspecialchars(currentUser()['display_name']); ?></strong>
            (<?php echo htmlspecialchars(currentUser()['role']); ?>)
            <a href="?logout=1" style="color:#e5f2ef; margin-left:0.5rem;">Abmelden</a>
        <?php endif; ?>
    </div>
    <div class="status">● Änderungen werden automatisch gespeichert</div>
</header>

<main>
    <?php foreach ($messages as $m): ?><div class="message">✔ <?php echo htmlspecialchars($m); ?></div><?php endforeach; ?>
    <?php foreach ($errors as $e): ?><div class="error">⚠ <?php echo htmlspecialchars($e); ?></div><?php endforeach; ?>

    <?php if (!isLoggedIn()): ?>
        <section class="section">
            <h2>Anmeldung</h2>
            <form method="post" class="form-grid">
                <input type="hidden" name="action" value="login">
                <label>Nutzername
                    <input name="username" required>
                </label>
                <label>Passwort
                    <input type="password" name="password" required>
                </label>
                <button type="submit">Anmelden</button>
            </form>
            <form method="post" class="form-grid" style="margin-top:1rem;">
                <input type="hidden" name="action" value="guest_login">
                <label>Gastcode (4-stellig)
                    <input name="guest_code" inputmode="numeric" pattern="\d{4}" required>
                </label>
                <button type="submit" class="btn-secondary">Als Gast einloggen</button>
            </form>
        </section>
    <?php else: ?>
        <section id="view-overview" class="view active">
            <div class="section">
                <h2>Rangliste & Guthaben</h2>
                <table class="leaderboard" id="leaderboard">
                    <thead>
                    <tr><th>Platz</th><th>Spieler</th><th>Punkte</th><th>Rest</th></tr>
                    </thead>
                    <tbody>
                    <?php foreach ($balances as $index => $row): ?>
                        <tr data-user-id="<?php echo $row['id']; ?>">
                            <td><?php echo $index + 1; ?></td>
                            <td>
                                <strong><?php echo htmlspecialchars($row['name']); ?></strong>
                                <?php if ($row['is_guest']): ?>
                                    <span class="pill">Gast</span>
                                <?php endif; ?>
                            </td>
                            <td><span data-role="points"><?php echo $row['points']; ?></span></td>
                            <td><strong data-role="remaining"><?php echo number_format($row['remaining'] / 100, 2, ',', '.'); ?> €</strong></td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            </div>

            <div class="section">
                <h2>Phasenliste</h2>
                <div class="phases-grid" id="phases-list">
                    <?php foreach ($phases as $phase): ?>
                        <div class="phase-card">
                            <h4>Phase <?php echo (int)$phase['phase_number']; ?></h4>
                            <p><?php echo htmlspecialchars($phase['title']); ?></p>
                            <?php if ($phase['info']): ?>
                                <p><?php echo nl2br(htmlspecialchars($phase['info'])); ?></p>
                            <?php endif; ?>
                        </div>
                    <?php endforeach; ?>
                </div>
            </div>
        </section>

        <section id="view-cards" class="view">
            <div class="card-stack" id="cards-stack">
                <?php foreach ($visibleUsers as $user): ?>
                    <?php $userId = (int)$user['id']; ?>
                    <article class="player-card" data-user-id="<?php echo $userId; ?>" style="border-color: <?php echo htmlspecialchars($user['color']); ?>">
                        <div class="header">
                            <div class="name"><?php echo htmlspecialchars($user['name']); ?></div>
                            <div class="chip" style="border-color: <?php echo htmlspecialchars($user['color']); ?>">Farbe</div>
                        </div>
                        <div class="stats">
                            <div class="stat">
                                <span>Punkte</span>
                                <strong data-role="points"><?php echo $user['points']; ?></strong>
                            </div>
                            <div class="stat">
                                <span>Guthaben</span>
                                <strong data-role="deposit"><?php echo number_format($user['deposit'] / 100, 2, ',', '.'); ?> €</strong>
                            </div>
                            <div class="stat">
                                <span>Rest</span>
                                <strong data-role="remaining"><?php echo number_format($user['remaining'] / 100, 2, ',', '.'); ?> €</strong>
                            </div>
                        </div>
                        <div class="phase-grid-card">
                            <?php for ($i = 1; $i <= 10; $i++): ?>
                                <?php $done = $progress[$userId][$i] ?? 0; ?>
                                <label class="phase-toggle">
                                    Phase <?php echo $i; ?>
                                    <input type="checkbox" data-role="phase" data-phase="<?php echo $i; ?>" data-user-id="<?php echo $userId; ?>" <?php echo $done ? 'checked' : ''; ?> <?php echo (!$isAdmin && $userId !== currentUser()['id']) ? 'disabled' : ''; ?>>
                                </label>
                            <?php endfor; ?>
                        </div>
                    </article>
                <?php endforeach; ?>
            </div>
        </section>

        <?php if ($isAdmin): ?>
            <section id="view-admin" class="view">
                <div class="section">
                    <h2>Admin: Spieler & Gäste</h2>
                    <form method="post" class="form-grid">
                        <input type="hidden" name="action" value="create_user">
                        <label>Nutzername<input name="username" required></label>
                        <label>Anzeigename<input name="display_name" required></label>
                        <label>Passwort<input type="password" name="password" required></label>
                        <label>Rolle
                            <select name="role">
                                <option value="player">Spieler</option>
                                <option value="admin">Admin</option>
                            </select>
                        </label>
                        <label>Farbe<input type="color" name="color" value="#2f8bff"></label>
                        <button type="submit">Spieler anlegen</button>
                    </form>

                    <form method="post" class="form-grid" style="margin-top:1.25rem;">
                        <input type="hidden" name="action" value="create_guest">
                        <label>Gastname<input name="display_name" required></label>
                        <label>Gastcode (4-stellig)
                            <input name="guest_code" inputmode="numeric" pattern="\d{4}" required>
                        </label>
                        <label>Startguthaben (€)
                            <input type="number" name="deposit_euro" step="0.01" min="0" value="0">
                        </label>
                        <label>Farbe<input type="color" name="color" value="#2f8bff"></label>
                        <button type="submit">Gast anlegen (24h)</button>
                    </form>
                </div>

                <div class="section">
                    <h2>Admin: Konten & Farben</h2>
                    <form method="post" class="form-grid">
                        <input type="hidden" name="action" value="update_deposit">
                        <label>Spieler
                            <select name="user_id">
                                <?php foreach ($balances as $row): ?>
                                    <option value="<?php echo $row['id']; ?>"><?php echo htmlspecialchars($row['name']); ?></option>
                                <?php endforeach; ?>
                            </select>
                        </label>
                        <label>Einzahlung (€)
                            <input type="number" name="deposit_euro" step="0.01" min="0" required>
                        </label>
                        <button type="submit">Einzahlung speichern</button>
                    </form>

                    <form method="post" class="form-grid" style="margin-top:1rem;">
                        <input type="hidden" name="action" value="rename_user">
                        <label>Spieler
                            <select name="user_id">
                                <?php foreach ($balances as $row): ?>
                                    <option value="<?php echo $row['id']; ?>"><?php echo htmlspecialchars($row['name']); ?></option>
                                <?php endforeach; ?>
                            </select>
                        </label>
                        <label>Neuer Anzeigename<input name="display_name" required></label>
                        <button type="submit">Name ändern</button>
                    </form>

                    <form method="post" class="form-grid" style="margin-top:1rem;">
                        <input type="hidden" name="action" value="update_color">
                        <label>Spieler
                            <select name="user_id">
                                <?php foreach ($balances as $row): ?>
                                    <option value="<?php echo $row['id']; ?>"><?php echo htmlspecialchars($row['name']); ?></option>
                                <?php endforeach; ?>
                            </select>
                        </label>
                        <label>Farbe<input type="color" name="color" value="#2f8bff"></label>
                        <button type="submit">Farbe ändern</button>
                    </form>

                    <form method="post" class="form-grid" style="margin-top:1rem;">
                        <input type="hidden" name="action" value="update_password">
                        <label>Spieler
                            <select name="user_id">
                                <?php foreach ($balances as $row): ?>
                                    <option value="<?php echo $row['id']; ?>"><?php echo htmlspecialchars($row['name']); ?></option>
                                <?php endforeach; ?>
                            </select>
                        </label>
                        <label>Neues Passwort<input type="password" name="password" required></label>
                        <button type="submit">Passwort ändern</button>
                    </form>
                </div>

                <div class="section">
                    <h2>Admin: Punkteverwaltung</h2>
                    <form method="post" class="form-grid">
                        <input type="hidden" name="action" value="add_score">
                        <label>Spieler
                            <select name="user_id">
                                <?php foreach ($balances as $row): ?>
                                    <option value="<?php echo $row['id']; ?>"><?php echo htmlspecialchars($row['name']); ?></option>
                                <?php endforeach; ?>
                            </select>
                        </label>
                        <label>Runde
                            <input type="number" name="round_number" min="1" value="1" required>
                        </label>
                        <label>Punkte (1 Punkt = 1 Cent)
                            <input type="number" name="points" step="1" required>
                        </label>
                        <button type="submit">Punkte speichern</button>
                    </form>

                    <h3 style="margin-top:1.25rem;">Letzte Punktänderungen</h3>
                    <table class="score-table" id="scores-table">
                        <thead><tr><th>Spieler</th><th>Runde</th><th>Punkte</th><th>Aktion</th></tr></thead>
                        <tbody>
                        <?php foreach ($scores as $score): ?>
                            <tr data-score-id="<?php echo $score['id']; ?>">
                                <td><?php echo htmlspecialchars($score['display_name']); ?></td>
                                <td><?php echo (int)$score['round_number']; ?></td>
                                <td><?php echo (int)$score['points']; ?></td>
                                <td>
                                    <div class="score-actions">
                                        <form method="post">
                                            <input type="hidden" name="score_id" value="<?php echo $score['id']; ?>">
                                            <input type="hidden" name="action" value="update_score">
                                            <input type="number" name="round_number" value="<?php echo $score['round_number']; ?>" min="1">
                                            <input type="number" name="points" value="<?php echo $score['points']; ?>">
                                            <button type="submit" class="btn-secondary">Update</button>
                                        </form>
                                        <form method="post">
                                            <input type="hidden" name="score_id" value="<?php echo $score['id']; ?>">
                                            <input type="hidden" name="action" value="delete_score">
                                            <button type="submit" class="danger">Löschen</button>
                                        </form>
                                    </div>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>

                <div class="section">
                    <h2>Admin: Phasenverwaltung</h2>
                    <div class="form-grid">
                        <?php foreach ($phases as $phase): ?>
                            <form method="post">
                                <input type="hidden" name="action" value="update_phase">
                                <input type="hidden" name="phase_number" value="<?php echo $phase['phase_number']; ?>">
                                <label>Phase <?php echo $phase['phase_number']; ?>
                                    <input name="title" value="<?php echo htmlspecialchars($phase['title']); ?>" required>
                                </label>
                                <label>Info
                                    <textarea name="info" rows="2"><?php echo htmlspecialchars($phase['info']); ?></textarea>
                                </label>
                                <button type="submit">Phase speichern</button>
                            </form>
                        <?php endforeach; ?>
                    </div>
                </div>
            </section>
        <?php endif; ?>
    <?php endif; ?>
</main>

<?php if (isLoggedIn()): ?>
    <nav class="tabs" id="tab-bar">
        <button type="button" data-target="view-overview" class="active">Übersicht</button>
        <button type="button" data-target="view-cards">Karten</button>
        <?php if ($isAdmin): ?>
            <button type="button" data-target="view-admin">Admin</button>
        <?php endif; ?>
    </nav>
<?php endif; ?>

<script>
    const tabs = document.querySelectorAll('.tabs button');
    tabs.forEach((tab) => {
        tab.addEventListener('click', () => {
            tabs.forEach(btn => btn.classList.remove('active'));
            tab.classList.add('active');
            document.querySelectorAll('.view').forEach(view => view.classList.remove('active'));
            const target = document.getElementById(tab.dataset.target);
            if (target) {
                target.classList.add('active');
            }
        });
    });

    async function updatePhase(userId, phaseNumber, completed = null) {
        const formData = new FormData();
        formData.append('action', completed === null ? 'toggle_phase' : 'set_phase');
        formData.append('user_id', userId);
        formData.append('phase_number', phaseNumber);
        if (completed !== null) {
            formData.append('completed', completed);
        }
        await fetch('index.php', {
            method: 'POST',
            body: formData
        });
    }

    document.querySelectorAll('[data-role="phase"]').forEach((checkbox) => {
        checkbox.addEventListener('change', () => {
            updatePhase(checkbox.dataset.userId, checkbox.dataset.phase, checkbox.checked ? 1 : 0);
        });
    });

    function renderBalances(balances) {
        const leaderboard = document.getElementById('leaderboard');
        if (!leaderboard) return;
        const tbody = leaderboard.querySelector('tbody');
        tbody.innerHTML = '';
        balances.forEach((row, index) => {
            const tr = document.createElement('tr');
            tr.dataset.userId = row.id;
            tr.innerHTML = `
                <td>${index + 1}</td>
                <td><strong>${row.name}</strong>${row.is_guest ? '<span class="pill">Gast</span>' : ''}</td>
                <td><span data-role="points">${row.points}</span></td>
                <td><strong data-role="remaining">${formatEuro(row.remaining)}</strong></td>
            `;
            tbody.appendChild(tr);
        });
    }

    function updateCards(balances, progress) {
        balances.forEach((row) => {
            const card = document.querySelector(`.player-card[data-user-id="${row.id}"]`);
            if (!card) return;
            card.querySelector('[data-role="points"]').textContent = row.points;
            card.querySelector('[data-role="deposit"]').textContent = formatEuro(row.deposit);
            card.querySelector('[data-role="remaining"]').textContent = formatEuro(row.remaining);
            const phases = progress[row.id] || {};
            card.querySelectorAll('[data-role="phase"]').forEach((checkbox) => {
                const phaseNum = checkbox.dataset.phase;
                const completed = phases[phaseNum] == 1;
                checkbox.checked = completed;
            });
        });
    }

    function renderScores(scores) {
        const table = document.getElementById('scores-table');
        if (!table) return;
        const tbody = table.querySelector('tbody');
        tbody.innerHTML = '';
        scores.forEach(score => {
            const tr = document.createElement('tr');
            tr.dataset.scoreId = score.id;
            tr.innerHTML = `
                <td>${score.display_name}</td>
                <td>${score.round_number}</td>
                <td>${score.points}</td>
                <td>
                    <div class="score-actions">
                        <form method="post">
                            <input type="hidden" name="score_id" value="${score.id}">
                            <input type="hidden" name="action" value="update_score">
                            <input type="number" name="round_number" value="${score.round_number}" min="1">
                            <input type="number" name="points" value="${score.points}">
                            <button type="submit" class="btn-secondary">Update</button>
                        </form>
                        <form method="post">
                            <input type="hidden" name="score_id" value="${score.id}">
                            <input type="hidden" name="action" value="delete_score">
                            <button type="submit" class="danger">Löschen</button>
                        </form>
                    </div>
                </td>
            `;
            tbody.appendChild(tr);
        });
    }

    function formatEuro(cents) {
        const euros = (cents / 100).toFixed(2).replace('.', ',');
        return `${euros} €`;
    }

    async function pollState() {
        try {
            const response = await fetch('index.php?ajax=state');
            if (!response.ok) return;
            const data = await response.json();
            if (!data.ok) return;
            renderBalances(data.balances);
            updateCards(data.balances, data.progress);
            if (data.isAdmin) {
                renderScores(data.scores);
            }
        } catch (error) {
            console.error(error);
        }
    }

    if (document.body.contains(document.getElementById('tab-bar'))) {
        setInterval(pollState, 5000);
    }
</script>
</body>
</html>
