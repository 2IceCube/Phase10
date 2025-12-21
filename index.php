<?php
require_once __DIR__ . '/db.php';

session_start();
$db = getDb();
$messages = [];
$errors = [];

function isLoggedIn(): bool
{
    return isset($_SESSION['user']);
}

function currentUser(): ?array
{
    return $_SESSION['user'] ?? null;
}

function isAdmin(): bool
{
    return isLoggedIn() && currentUser()['role'] === 'admin';
}

function cleanupExpiredGuests(PDO $db): void
{
    $db->exec('DELETE FROM users WHERE guest_expires_at IS NOT NULL AND datetime(guest_expires_at) <= datetime("now")');
}

function refreshUser(PDO $db): void
{
    if (!isLoggedIn()) {
        return;
    }
    $stmt = $db->prepare('SELECT id, username, display_name, role, deposit_cents, color, guest_expires_at FROM users WHERE id = :id');
    $stmt->execute([':id' => $_SESSION['user']['id']]);
    if ($row = $stmt->fetch()) {
        $_SESSION['user'] = $row;
        if (!empty($row['guest_expires_at'])) {
            $expires = strtotime($row['guest_expires_at']);
            if ($expires !== false && $expires <= time()) {
                session_destroy();
            }
        }
    } else {
        session_destroy();
    }
}

function requireAdmin(): void
{
    if (!isAdmin()) {
        header('HTTP/1.1 403 Forbidden');
        echo '<h2>Zugriff verweigert</h2>';
        exit;
    }
}

function sumPoints(PDO $db, int $userId): int
{
    $stmt = $db->prepare('SELECT COALESCE(SUM(points), 0) FROM scores WHERE user_id = :id');
    $stmt->execute([':id' => $userId]);
    return (int)$stmt->fetchColumn();
}

function getPlayers(PDO $db): array
{
    $stmt = $db->query('SELECT id, display_name, deposit_cents, color, guest_expires_at FROM users WHERE role = "player" ORDER BY display_name');
    return $stmt->fetchAll();
}

function getBalances(PDO $db): array
{
    $rows = getPlayers($db);
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

function getScores(PDO $db, int $limit = 40): array
{
    $stmt = $db->prepare('SELECT s.id, s.round_number, s.points, s.created_at, u.display_name FROM scores s JOIN users u ON u.id = s.user_id ORDER BY s.round_number DESC, s.id DESC LIMIT :lim');
    $stmt->bindValue(':lim', $limit, PDO::PARAM_INT);
    $stmt->execute();
    return $stmt->fetchAll();
}

function ensurePhaseProgress(PDO $db, int $userId): void
{
    $existing = $db->prepare('SELECT phase_number FROM phase_progress WHERE user_id = :u');
    $existing->execute([':u' => $userId]);
    $rows = $existing->fetchAll(PDO::FETCH_COLUMN, 0);
    $missing = array_diff(range(1, 10), array_map('intval', $rows));
    if (!$missing) {
        return;
    }
    $insert = $db->prepare('INSERT INTO phase_progress (user_id, phase_number, completed) VALUES (:u, :p, 0)');
    foreach ($missing as $phase) {
        $insert->execute([':u' => $userId, ':p' => $phase]);
    }
}

function getPhaseProgress(PDO $db, array $userIds): array
{
    $progress = [];
    foreach ($userIds as $userId) {
        ensurePhaseProgress($db, $userId);
    }
    if (!$userIds) {
        return $progress;
    }
    $placeholders = implode(',', array_fill(0, count($userIds), '?'));
    $stmt = $db->prepare('SELECT user_id, phase_number, completed FROM phase_progress WHERE user_id IN (' . $placeholders . ')');
    $stmt->execute($userIds);
    foreach ($stmt->fetchAll() as $row) {
        $progress[(int)$row['user_id']][(int)$row['phase_number']] = (int)$row['completed'];
    }
    return $progress;
}

function buildState(PDO $db, bool $isAdmin): array
{
    $balances = getBalances($db);
    $phases = getPhases($db);
    $playerIds = array_map(fn($row) => (int)$row['id'], $balances);
    $progress = getPhaseProgress($db, $playerIds);

    return [
        'user' => currentUser(),
        'balances' => $balances,
        'phases' => $phases,
        'progress' => $progress,
        'scores' => $isAdmin ? getScores($db) : [],
        'serverTime' => date('c'),
    ];
}

cleanupExpiredGuests($db);
refreshUser($db);

if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: index.php');
    exit;
}

if (isset($_GET['api'])) {
    header('Content-Type: application/json; charset=utf-8');
    if (!isLoggedIn()) {
        http_response_code(403);
        echo json_encode(['error' => 'unauthorized']);
        exit;
    }
    $api = $_GET['api'];
    if ($api === 'state') {
        echo json_encode(buildState($db, isAdmin()));
        exit;
    }
    if ($api === 'toggle_phase') {
        $userId = (int)($_POST['user_id'] ?? 0);
        $phaseNumber = (int)($_POST['phase_number'] ?? 0);
        $completed = isset($_POST['completed']) && (int)$_POST['completed'] === 1 ? 1 : 0;
        if (!$userId || $phaseNumber < 1 || $phaseNumber > 10) {
            http_response_code(400);
            echo json_encode(['error' => 'invalid']);
            exit;
        }
        if (!isAdmin() && currentUser()['id'] !== $userId) {
            http_response_code(403);
            echo json_encode(['error' => 'forbidden']);
            exit;
        }
        ensurePhaseProgress($db, $userId);
        $stmt = $db->prepare('UPDATE phase_progress SET completed = :c, updated_at = CURRENT_TIMESTAMP WHERE user_id = :u AND phase_number = :p');
        $stmt->execute([':c' => $completed, ':u' => $userId, ':p' => $phaseNumber]);
        echo json_encode(['ok' => true]);
        exit;
    }
    http_response_code(404);
    echo json_encode(['error' => 'not_found']);
    exit;
}

if (isset($_POST['action']) && $_POST['action'] === 'login') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $stmt = $db->prepare('SELECT id, username, display_name, password_hash, role, deposit_cents, color, guest_expires_at FROM users WHERE username = :u');
    $stmt->execute([':u' => $username]);
    if ($user = $stmt->fetch()) {
        if (password_verify($password, $user['password_hash'])) {
            $_SESSION['user'] = $user;
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
        $stmt = $db->prepare('SELECT id, username, display_name, role, deposit_cents, color, guest_expires_at FROM users WHERE guest_code = :c AND guest_expires_at IS NOT NULL AND datetime(guest_expires_at) > datetime("now")');
        $stmt->execute([':c' => $code]);
        if ($user = $stmt->fetch()) {
            $_SESSION['user'] = $user;
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
    $color = trim($_POST['color'] ?? '#1f6feb');
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
    $display = trim($_POST['guest_name'] ?? '');
    $deposit = (int)round((float)($_POST['guest_deposit'] ?? 0) * 100);
    $color = trim($_POST['guest_color'] ?? '#22c55e');
    $code = trim($_POST['guest_code'] ?? '');
    if (!$display || !preg_match('/^\d{4}$/', $code)) {
        $errors[] = 'Bitte Gastname und 4-stelligen Code angeben.';
    } else {
        $username = 'guest_' . $code . '_' . time();
        $password = bin2hex(random_bytes(6));
        $expires = date('Y-m-d H:i:s', time() + 24 * 3600);
        $stmt = $db->prepare('INSERT INTO users (username, display_name, password_hash, role, color, deposit_cents, guest_code, guest_expires_at) VALUES (:u, :d, :p, "player", :c, :dep, :gc, :ge)');
        try {
            $stmt->execute([
                ':u' => $username,
                ':d' => $display,
                ':p' => password_hash($password, PASSWORD_DEFAULT),
                ':c' => $color,
                ':dep' => $deposit,
                ':gc' => $code,
                ':ge' => $expires,
            ]);
            $messages[] = 'Gastzugang wurde angelegt (läuft in 24h ab).';
        } catch (PDOException $e) {
            $errors[] = 'Fehler beim Anlegen: ' . htmlspecialchars($e->getMessage());
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

if (isset($_POST['action']) && $_POST['action'] === 'update_color') {
    requireAdmin();
    $userId = (int)($_POST['user_id'] ?? 0);
    $color = trim($_POST['color'] ?? '#1f6feb');
    $stmt = $db->prepare('UPDATE users SET color = :c WHERE id = :id');
    $stmt->execute([':c' => $color, ':id' => $userId]);
    $messages[] = 'Farbe aktualisiert.';
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

refreshUser($db);

$isAdmin = isAdmin();
$hasAccess = isLoggedIn();
$balances = $hasAccess ? getBalances($db) : [];
$phases = $hasAccess ? getPhases($db) : [];
$scores = $isAdmin ? getScores($db) : [];
$state = $hasAccess ? buildState($db, $isAdmin) : null;
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
            --bg: #f2f4f8;
            --card-bg: #ffffff;
            --text: #1f2933;
            --muted: #5f6c7b;
            --primary: #25d366;
            --dark: #0b141a;
            --border: #e5e7eb;
        }
        * { box-sizing: border-box; }
        body {
            margin: 0;
            font-family: "Segoe UI", system-ui, -apple-system, sans-serif;
            background: var(--bg);
            color: var(--text);
        }
        .app {
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }
        .app-header {
            background: var(--dark);
            color: #fff;
            padding: 1rem;
            display: flex;
            flex-direction: column;
            gap: .5rem;
        }
        .header-top {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .header-title {
            font-size: 1.2rem;
            font-weight: 700;
        }
        .user-info {
            font-size: .85rem;
            color: #cdd6dd;
        }
        .sync-status {
            display: inline-flex;
            align-items: center;
            gap: .4rem;
            font-size: .75rem;
            color: #cdd6dd;
        }
        .sync-dot {
            width: .45rem;
            height: .45rem;
            border-radius: 999px;
            background: var(--primary);
            display: inline-block;
        }
        .content {
            flex: 1;
            padding: 1rem;
            padding-bottom: 5.5rem;
        }
        .card {
            background: var(--card-bg);
            border-radius: 18px;
            padding: 1rem;
            box-shadow: 0 6px 20px rgba(15, 23, 42, 0.08);
            border: 1px solid var(--border);
        }
        .stack { display: grid; gap: 1rem; }
        .message { color: #0b6e4f; font-weight: 600; }
        .error { color: #b3261e; font-weight: 600; }
        .section-title {
            font-size: 1rem;
            margin: 0 0 .75rem;
        }
        .tab-section { display: none; }
        .tab-section.active { display: block; }
        .login-grid { display: grid; gap: 1rem; }
        label { font-size: .85rem; color: var(--muted); }
        input, select, button, textarea {
            width: 100%;
            padding: .7rem .8rem;
            border-radius: 12px;
            border: 1px solid var(--border);
            font-size: 1rem;
            margin-top: .35rem;
        }
        button {
            background: var(--primary);
            color: #fff;
            font-weight: 600;
            border: none;
            cursor: pointer;
        }
        button.secondary {
            background: #1f6feb;
        }
        button.ghost {
            background: #e2e8f0;
            color: #1f2933;
        }
        .bottom-nav {
            position: fixed;
            bottom: 0;
            left: 0;
            right: 0;
            display: flex;
            justify-content: space-around;
            background: #fff;
            border-top: 1px solid var(--border);
            padding: .6rem .4rem;
        }
        .bottom-nav button {
            background: transparent;
            color: var(--muted);
            border: none;
            font-size: .85rem;
            font-weight: 600;
        }
        .bottom-nav button.active {
            color: var(--primary);
        }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: .85rem;
        }
        th, td {
            padding: .6rem .4rem;
            border-bottom: 1px solid var(--border);
            text-align: left;
        }
        th { color: var(--muted); font-weight: 600; }
        .phase-list {
            display: grid;
            gap: .75rem;
        }
        .phase-item {
            padding: .75rem;
            border-radius: 14px;
            border: 1px solid var(--border);
            background: #f8fafc;
        }
        .cards-container {
            display: flex;
            gap: 1rem;
            overflow-x: auto;
            scroll-snap-type: x mandatory;
            padding-bottom: 1rem;
        }
        .player-card {
            min-width: calc(100% - 1rem);
            scroll-snap-align: start;
            background: linear-gradient(145deg, #fefefe, #eef2f7);
            border-radius: 24px;
            padding: 1.2rem;
            border: 2px solid rgba(0,0,0,0.08);
            position: relative;
        }
        .player-card::after {
            content: "";
            position: absolute;
            inset: .8rem;
            border-radius: 18px;
            border: 2px dashed rgba(0,0,0,0.08);
            pointer-events: none;
        }
        .player-card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: .8rem;
        }
        .player-name {
            font-size: 1.2rem;
            font-weight: 700;
        }
        .player-color {
            width: 18px;
            height: 18px;
            border-radius: 50%;
            border: 2px solid #fff;
            box-shadow: 0 0 0 2px rgba(0,0,0,0.08);
        }
        .player-stats {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: .6rem;
            margin-bottom: .8rem;
        }
        .stat {
            background: #fff;
            padding: .65rem;
            border-radius: 12px;
            border: 1px solid var(--border);
        }
        .stat-label { font-size: .7rem; color: var(--muted); }
        .stat-value { font-size: 1rem; font-weight: 700; }
        .phase-grid {
            display: grid;
            grid-template-columns: repeat(5, minmax(0, 1fr));
            gap: .6rem;
        }
        .phase-toggle {
            display: grid;
            place-items: center;
            border-radius: 12px;
            border: 2px solid var(--border);
            background: #fff;
            padding: .4rem;
        }
        .phase-toggle input {
            width: 1.4rem;
            height: 1.4rem;
        }
        .phase-toggle span { font-size: .8rem; color: var(--muted); }
        .admin-grid { display: grid; gap: 1rem; }
        .mini { font-size: .75rem; color: var(--muted); }
        .badge {
            display: inline-flex;
            align-items: center;
            gap: .35rem;
            background: #e2f8ed;
            color: #067647;
            font-weight: 600;
            padding: .2rem .5rem;
            border-radius: 999px;
            font-size: .7rem;
        }
        .logout-link { color: #cdd6dd; text-decoration: none; font-size: .8rem; }
        @media (min-width: 768px) {
            .cards-container { overflow-x: hidden; flex-wrap: wrap; }
            .player-card { min-width: 320px; width: 48%; }
        }
    </style>
</head>
<body>
<div class="app">
    <header class="app-header">
        <div class="header-top">
            <div class="header-title">Phase 10 Liveboard</div>
            <div>
                <?php if ($hasAccess): ?>
                    <a class="logout-link" href="?logout=1">Abmelden</a>
                <?php endif; ?>
            </div>
        </div>
        <div class="user-info">
            <?php if ($hasAccess): ?>
                Angemeldet als <strong><?php echo htmlspecialchars(currentUser()['display_name']); ?></strong>
                (<?php echo htmlspecialchars(currentUser()['role']); ?>)
            <?php else: ?>
                Bitte anmelden oder Gastcode verwenden.
            <?php endif; ?>
        </div>
        <div class="sync-status" id="sync-status">
            <span class="sync-dot" id="sync-dot"></span>
            Änderungen werden automatisch gespeichert
        </div>
    </header>

    <main class="content">
        <?php foreach ($messages as $m): ?><div class="message">✔ <?php echo htmlspecialchars($m); ?></div><?php endforeach; ?>
        <?php foreach ($errors as $e): ?><div class="error">⚠ <?php echo htmlspecialchars($e); ?></div><?php endforeach; ?>

        <?php if (!$hasAccess): ?>
            <section class="card login-grid">
                <h2 class="section-title">Anmeldung</h2>
                <form method="post">
                    <input type="hidden" name="action" value="login">
                    <label>Nutzername
                        <input name="username" required>
                    </label>
                    <label>Passwort
                        <input type="password" name="password" required>
                    </label>
                    <button type="submit">Anmelden</button>
                </form>
                <form method="post">
                    <input type="hidden" name="action" value="guest_login">
                    <label>Gastcode (4-stellig)
                        <input name="guest_code" inputmode="numeric" pattern="\d{4}" maxlength="4" required>
                    </label>
                    <button type="submit" class="secondary">Mit Gastcode starten</button>
                </form>
            </section>
        <?php endif; ?>

        <?php if ($hasAccess): ?>
        <section id="tab-overview" class="tab-section active stack">
            <div class="card">
                <h2 class="section-title">Rangliste</h2>
                <?php if ($currentWinner): ?>
                    <div class="badge">🏆 Gewinner: <?php echo htmlspecialchars($currentWinner['name']); ?></div>
                <?php endif; ?>
                <table>
                    <thead>
                    <tr><th>#</th><th>Spieler</th><th>Punkte</th><th>Rest</th></tr>
                    </thead>
                    <tbody id="balances-body">
                    <?php foreach ($balances as $index => $row): ?>
                        <tr>
                            <td><?php echo $index + 1; ?></td>
                            <td><?php echo htmlspecialchars($row['name']); ?></td>
                            <td><?php echo $row['points']; ?></td>
                            <td><strong><?php echo number_format($row['remaining']/100, 2, ',', '.'); ?> €</strong></td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            </div>

            <div class="card">
                <h2 class="section-title">Phasenliste</h2>
                <div class="phase-list" id="phases-list">
                    <?php foreach ($phases as $phase): ?>
                        <div class="phase-item">
                            <strong>Phase <?php echo (int)$phase['phase_number']; ?>:</strong>
                            <?php echo htmlspecialchars($phase['title']); ?><br>
                            <span class="mini"><?php echo nl2br(htmlspecialchars($phase['info'])); ?></span>
                        </div>
                    <?php endforeach; ?>
                </div>
            </div>
        </section>

        <section id="tab-cards" class="tab-section">
            <h2 class="section-title">Spielerkarten</h2>
            <div class="cards-container" id="cards-container"></div>
        </section>
        <?php endif; ?>

        <?php if ($isAdmin): ?>
        <section id="tab-admin" class="tab-section stack">
            <div class="card admin-grid">
                <h2 class="section-title">Admin: Spieler & Gäste</h2>
                <form method="post">
                    <input type="hidden" name="action" value="create_user">
                    <h3>Neuen Account anlegen</h3>
                    <label>Nutzername<input name="username" required></label>
                    <label>Anzeigename<input name="display_name" required></label>
                    <label>Passwort<input type="password" name="password" required></label>
                    <label>Farbe<input type="color" name="color" value="#1f6feb"></label>
                    <label>Rolle
                        <select name="role">
                            <option value="player">Spieler</option>
                            <option value="admin">Admin</option>
                        </select>
                    </label>
                    <button type="submit">Speichern</button>
                </form>

                <form method="post">
                    <input type="hidden" name="action" value="create_guest">
                    <h3>Gastzugang erstellen</h3>
                    <label>Name<input name="guest_name" required></label>
                    <label>Guthaben (€)<input type="number" name="guest_deposit" step="0.01" min="0" required></label>
                    <label>Farbe<input type="color" name="guest_color" value="#22c55e"></label>
                    <label>Gastcode (4-stellig)<input name="guest_code" inputmode="numeric" pattern="\d{4}" maxlength="4" required></label>
                    <button type="submit" class="secondary">Gast anlegen</button>
                    <div class="mini">Gastkonto läuft 24 Stunden nach Erstellung ab.</div>
                </form>
            </div>

            <div class="card admin-grid">
                <h2 class="section-title">Admin: Pflege</h2>
                <form method="post">
                    <input type="hidden" name="action" value="update_password">
                    <h3>Passwort ändern</h3>
                    <label>Spieler
                        <select name="user_id" class="player-select">
                            <?php foreach ($balances as $row): ?>
                                <option value="<?php echo $row['id']; ?>"><?php echo htmlspecialchars($row['name']); ?></option>
                            <?php endforeach; ?>
                        </select>
                    </label>
                    <label>Neues Passwort<input type="password" name="password" required></label>
                    <button type="submit">Aktualisieren</button>
                </form>

                <form method="post">
                    <input type="hidden" name="action" value="rename_user">
                    <h3>Namen ändern</h3>
                    <label>Spieler
                        <select name="user_id" class="player-select">
                            <?php foreach ($balances as $row): ?>
                                <option value="<?php echo $row['id']; ?>"><?php echo htmlspecialchars($row['name']); ?></option>
                            <?php endforeach; ?>
                        </select>
                    </label>
                    <label>Neuer Anzeigename<input name="display_name" required></label>
                    <button type="submit">Speichern</button>
                </form>

                <form method="post">
                    <input type="hidden" name="action" value="update_color">
                    <h3>Farbe ändern</h3>
                    <label>Spieler
                        <select name="user_id" class="player-select">
                            <?php foreach ($balances as $row): ?>
                                <option value="<?php echo $row['id']; ?>"><?php echo htmlspecialchars($row['name']); ?></option>
                            <?php endforeach; ?>
                        </select>
                    </label>
                    <label>Farbe<input type="color" name="color" value="#1f6feb"></label>
                    <button type="submit">Aktualisieren</button>
                </form>
            </div>

            <div class="card admin-grid">
                <h2 class="section-title">Admin: Einzahlungen & Punkte</h2>
                <form method="post">
                    <input type="hidden" name="action" value="update_deposit">
                    <h3>Einzahlung hinterlegen</h3>
                    <label>Spieler
                        <select name="user_id" class="player-select">
                            <?php foreach ($balances as $row): ?>
                                <option value="<?php echo $row['id']; ?>"><?php echo htmlspecialchars($row['name']); ?></option>
                            <?php endforeach; ?>
                        </select>
                    </label>
                    <label>Einzahlung (€)
                        <input type="number" name="deposit_euro" step="0.01" min="0" required>
                    </label>
                    <button type="submit">Speichern</button>
                </form>

                <form method="post">
                    <input type="hidden" name="action" value="add_score">
                    <h3>Punkte eintragen</h3>
                    <label>Spieler
                        <select name="user_id" class="player-select">
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
                    <button type="submit">Speichern</button>
                </form>
            </div>

            <div class="card">
                <h2 class="section-title">Letzte Punktänderungen</h2>
                <table>
                    <thead><tr><th>Spieler</th><th>Runde</th><th>Punkte</th><th>Datum</th><th>Aktion</th></tr></thead>
                    <tbody id="scores-body">
                    <?php foreach ($scores as $score): ?>
                        <tr>
                            <td><?php echo htmlspecialchars($score['display_name']); ?></td>
                            <td><?php echo (int)$score['round_number']; ?></td>
                            <td><?php echo (int)$score['points']; ?></td>
                            <td><?php echo htmlspecialchars($score['created_at']); ?></td>
                            <td>
                                <form method="post" style="display:flex; gap:.5rem; flex-wrap:wrap; align-items:center;">
                                    <input type="hidden" name="score_id" value="<?php echo $score['id']; ?>">
                                    <input type="hidden" name="action" value="update_score">
                                    <input type="number" name="round_number" value="<?php echo $score['round_number']; ?>" min="1" style="width:80px;">
                                    <input type="number" name="points" value="<?php echo $score['points']; ?>" style="width:80px;">
                                    <button type="submit" class="ghost">Aktualisieren</button>
                                </form>
                                <form method="post">
                                    <input type="hidden" name="score_id" value="<?php echo $score['id']; ?>">
                                    <input type="hidden" name="action" value="delete_score">
                                    <button type="submit" class="ghost">Löschen</button>
                                </form>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            </div>

            <div class="card admin-grid">
                <h2 class="section-title">Phasenverwaltung</h2>
                <?php foreach ($phases as $phase): ?>
                    <form method="post">
                        <input type="hidden" name="action" value="update_phase">
                        <input type="hidden" name="phase_number" value="<?php echo $phase['phase_number']; ?>">
                        <div><strong>Phase <?php echo $phase['phase_number']; ?></strong></div>
                        <label>Titel
                            <input name="title" value="<?php echo htmlspecialchars($phase['title']); ?>" required>
                        </label>
                        <label>Info
                            <textarea name="info" rows="3"><?php echo htmlspecialchars($phase['info']); ?></textarea>
                        </label>
                        <button type="submit" class="ghost">Speichern</button>
                    </form>
                <?php endforeach; ?>
            </div>
        </section>
        <?php endif; ?>
    </main>

    <?php if ($hasAccess): ?>
    <nav class="bottom-nav" id="bottom-nav">
        <button type="button" data-tab="overview" class="active">Übersicht</button>
        <button type="button" data-tab="cards">Karten</button>
        <?php if ($isAdmin): ?>
            <button type="button" data-tab="admin">Admin</button>
        <?php endif; ?>
    </nav>
    <?php endif; ?>
</div>

<script>
    const hasAccess = <?php echo json_encode($hasAccess); ?>;
    const isAdmin = <?php echo json_encode($isAdmin); ?>;
    let state = <?php echo json_encode($state); ?>;

    function setActiveTab(tab) {
        document.querySelectorAll('.tab-section').forEach(section => {
            section.classList.toggle('active', section.id === `tab-${tab}`);
        });
        document.querySelectorAll('.bottom-nav button').forEach(button => {
            button.classList.toggle('active', button.dataset.tab === tab);
        });
    }

    function renderBalances(balances) {
        const body = document.getElementById('balances-body');
        if (!body) return;
        body.innerHTML = balances.map((row, index) => `
            <tr>
                <td>${index + 1}</td>
                <td>${row.name}</td>
                <td>${row.points}</td>
                <td><strong>${(row.remaining / 100).toFixed(2).replace('.', ',')} €</strong></td>
            </tr>
        `).join('');
    }

    function renderPhases(phases) {
        const list = document.getElementById('phases-list');
        if (!list) return;
        list.innerHTML = phases.map(phase => `
            <div class="phase-item">
                <strong>Phase ${phase.phase_number}:</strong> ${phase.title}<br>
                <span class="mini">${phase.info ? phase.info.replace(/\n/g, '<br>') : ''}</span>
            </div>
        `).join('');
    }

    function renderCards(balances, progress) {
        const container = document.getElementById('cards-container');
        if (!container) return;
        const allowedIds = isAdmin ? balances.map(row => row.id) : [state.user.id];
        container.innerHTML = balances.filter(row => allowedIds.includes(row.id)).map(row => {
            const phases = Array.from({length: 10}, (_, i) => {
                const phaseNum = i + 1;
                const checked = progress?.[row.id]?.[phaseNum] ? 'checked' : '';
                const disabled = (!isAdmin && row.id !== state.user.id) ? 'disabled' : '';
                return `
                    <label class="phase-toggle" data-user-id="${row.id}" data-phase="${phaseNum}">
                        <input type="checkbox" ${checked} ${disabled}>
                        <span>${phaseNum}</span>
                    </label>
                `;
            }).join('');

            return `
                <article class="player-card" style="border-color:${row.color}">
                    <div class="player-card-header">
                        <div class="player-name">${row.name}</div>
                        <div class="player-color" style="background:${row.color}"></div>
                    </div>
                    <div class="player-stats">
                        <div class="stat">
                            <div class="stat-label">Punkte</div>
                            <div class="stat-value">${row.points}</div>
                        </div>
                        <div class="stat">
                            <div class="stat-label">Restguthaben</div>
                            <div class="stat-value">${(row.remaining / 100).toFixed(2).replace('.', ',')} €</div>
                        </div>
                        <div class="stat">
                            <div class="stat-label">Einzahlung</div>
                            <div class="stat-value">${(row.deposit / 100).toFixed(2).replace('.', ',')} €</div>
                        </div>
                        <div class="stat">
                            <div class="stat-label">Fortschritt</div>
                            <div class="stat-value">${Object.values(progress?.[row.id] || {}).filter(Boolean).length}/10</div>
                        </div>
                    </div>
                    <div class="phase-grid">${phases}</div>
                </article>
            `;
        }).join('');
    }

    function renderScores(scores) {
        const body = document.getElementById('scores-body');
        if (!body) return;
        body.innerHTML = scores.map(score => `
            <tr>
                <td>${score.display_name}</td>
                <td>${score.round_number}</td>
                <td>${score.points}</td>
                <td>${score.created_at}</td>
                <td>
                    <form method="post" style="display:flex; gap:.5rem; flex-wrap:wrap; align-items:center;">
                        <input type="hidden" name="score_id" value="${score.id}">
                        <input type="hidden" name="action" value="update_score">
                        <input type="number" name="round_number" value="${score.round_number}" min="1" style="width:80px;">
                        <input type="number" name="points" value="${score.points}" style="width:80px;">
                        <button type="submit" class="ghost">Aktualisieren</button>
                    </form>
                    <form method="post">
                        <input type="hidden" name="score_id" value="${score.id}">
                        <input type="hidden" name="action" value="delete_score">
                        <button type="submit" class="ghost">Löschen</button>
                    </form>
                </td>
            </tr>
        `).join('');
    }

    function renderPlayerSelects(balances) {
        document.querySelectorAll('.player-select').forEach(select => {
            const value = select.value;
            select.innerHTML = balances.map(row => `<option value="${row.id}">${row.name}</option>`).join('');
            if ([...select.options].some(option => option.value === value)) {
                select.value = value;
            }
        });
    }

    function renderAll(nextState) {
        if (!nextState) return;
        renderBalances(nextState.balances);
        renderPhases(nextState.phases);
        renderCards(nextState.balances, nextState.progress);
        if (isAdmin) {
            renderScores(nextState.scores);
            renderPlayerSelects(nextState.balances);
        }
    }

    async function fetchState() {
        if (!hasAccess) return;
        const dot = document.getElementById('sync-dot');
        try {
            dot.style.background = '#fbbf24';
            const response = await fetch('?api=state');
            if (!response.ok) {
                dot.style.background = '#ef4444';
                return;
            }
            state = await response.json();
            renderAll(state);
            dot.style.background = '#22c55e';
        } catch (error) {
            dot.style.background = '#ef4444';
        }
    }

    async function updatePhase(userId, phaseNumber, completed) {
        const dot = document.getElementById('sync-dot');
        try {
            dot.style.background = '#fbbf24';
            const formData = new FormData();
            formData.append('user_id', userId);
            formData.append('phase_number', phaseNumber);
            formData.append('completed', completed ? '1' : '0');
            const response = await fetch('?api=toggle_phase', { method: 'POST', body: formData });
            if (!response.ok) {
                dot.style.background = '#ef4444';
                return;
            }
            dot.style.background = '#22c55e';
        } catch (error) {
            dot.style.background = '#ef4444';
        }
    }

    if (hasAccess) {
        renderAll(state);
        setInterval(fetchState, 5000);
        document.getElementById('bottom-nav')?.addEventListener('click', event => {
            if (event.target.matches('button[data-tab]')) {
                setActiveTab(event.target.dataset.tab);
            }
        });
        document.getElementById('cards-container')?.addEventListener('change', event => {
            const wrapper = event.target.closest('.phase-toggle');
            if (!wrapper) return;
            const userId = wrapper.dataset.userId;
            const phaseNumber = wrapper.dataset.phase;
            updatePhase(userId, phaseNumber, event.target.checked);
        });
    }
</script>
</body>
</html>
