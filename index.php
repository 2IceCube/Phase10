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
    return isLoggedIn() && ($_SESSION['user']['role'] ?? '') === 'admin';
}

function requireLogin(): void
{
    if (!isLoggedIn()) {
        header('HTTP/1.1 403 Forbidden');
        echo json_encode(['error' => 'Nicht eingeloggt.']);
        exit;
    }
}

function requireAdmin(): void
{
    if (!isAdmin()) {
        header('HTTP/1.1 403 Forbidden');
        echo json_encode(['error' => 'Zugriff verweigert.']);
        exit;
    }
}

function cleanupExpiredGuests(PDO $db): void
{
    $now = (new DateTimeImmutable('now'))->format(DateTimeInterface::ATOM);
    $stmt = $db->prepare('DELETE FROM users WHERE role = "guest" AND guest_expires_at IS NOT NULL AND guest_expires_at <= :now');
    $stmt->execute([':now' => $now]);
}

function refreshUser(PDO $db): void
{
    if (!isLoggedIn()) {
        return;
    }

    $stmt = $db->prepare('SELECT id, username, display_name, role, deposit_cents, color, guest_expires_at FROM users WHERE id = :id');
    $stmt->execute([':id' => $_SESSION['user']['id']]);
    if ($row = $stmt->fetch()) {
        if ($row['role'] === 'guest' && $row['guest_expires_at']) {
            $expires = DateTimeImmutable::createFromFormat(DateTimeInterface::ATOM, $row['guest_expires_at']);
            if ($expires && $expires <= new DateTimeImmutable('now')) {
                session_destroy();
                return;
            }
        }
        $_SESSION['user'] = $row;
    } else {
        session_destroy();
    }
}

function sumPoints(PDO $db, int $userId): int
{
    $stmt = $db->prepare('SELECT COALESCE(SUM(points), 0) FROM scores WHERE user_id = :id');
    $stmt->execute([':id' => $userId]);
    return (int)$stmt->fetchColumn();
}

function getBalances(PDO $db): array
{
    $stmt = $db->query('SELECT id, display_name, deposit_cents FROM users WHERE role IN ("player", "guest") ORDER BY display_name');
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

function getPhaseStatus(PDO $db, int $userId): array
{
    $stmt = $db->prepare('SELECT phase_number, completed FROM player_phases WHERE user_id = :id ORDER BY phase_number');
    $stmt->execute([':id' => $userId]);
    $rows = $stmt->fetchAll();
    $status = [];
    foreach ($rows as $row) {
        $status[] = [
            'phase_number' => (int)$row['phase_number'],
            'completed' => (int)$row['completed'],
        ];
    }
    return $status;
}

function getCards(PDO $db, ?int $userId = null): array
{
    if ($userId) {
        $stmt = $db->prepare('SELECT id, display_name, deposit_cents, color FROM users WHERE id = :id AND role IN ("player", "guest")');
        $stmt->execute([':id' => $userId]);
        $users = $stmt->fetchAll();
    } else {
        $stmt = $db->query('SELECT id, display_name, deposit_cents, color FROM users WHERE role IN ("player", "guest") ORDER BY display_name');
        $users = $stmt->fetchAll();
    }

    $cards = [];
    foreach ($users as $user) {
        $points = sumPoints($db, (int)$user['id']);
        $remaining = (int)$user['deposit_cents'] - $points;
        $cards[] = [
            'id' => (int)$user['id'],
            'name' => $user['display_name'],
            'deposit' => (int)$user['deposit_cents'],
            'points' => $points,
            'remaining' => $remaining,
            'color' => $user['color'],
            'phases' => getPhaseStatus($db, (int)$user['id']),
        ];
    }

    return $cards;
}

function getScores(PDO $db, int $limit = 40): array
{
    $stmt = $db->prepare('SELECT s.id, s.round_number, s.points, s.created_at, u.display_name FROM scores s JOIN users u ON u.id = s.user_id ORDER BY s.round_number DESC, s.id DESC LIMIT :lim');
    $stmt->bindValue(':lim', $limit, PDO::PARAM_INT);
    $stmt->execute();
    return $stmt->fetchAll();
}

cleanupExpiredGuests($db);
refreshUser($db);

if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: index.php');
    exit;
}

if (isset($_GET['ajax'])) {
    $action = $_GET['ajax'];
    header('Content-Type: application/json');

    if ($action === 'state') {
        if (!isLoggedIn()) {
            echo json_encode(['logged_in' => false]);
            exit;
        }

        $user = currentUser();
        $isAdmin = isAdmin();
        $balances = getBalances($db);
        $phases = getPhases($db);
        $cards = getCards($db, $isAdmin ? null : (int)$user['id']);
        $scores = $isAdmin ? getScores($db) : [];

        echo json_encode([
            'logged_in' => true,
            'user' => $user,
            'is_admin' => $isAdmin,
            'balances' => $balances,
            'phases' => $phases,
            'cards' => $cards,
            'scores' => $scores,
        ]);
        exit;
    }

    if ($action === 'update_phase') {
        requireLogin();
        $userId = (int)($_POST['user_id'] ?? 0);
        $phaseNumber = (int)($_POST['phase_number'] ?? 0);
        $completed = (int)($_POST['completed'] ?? 0) === 1 ? 1 : 0;

        if (!isAdmin()) {
            $userId = (int)currentUser()['id'];
        }

        if ($userId && $phaseNumber >= 1 && $phaseNumber <= 10) {
            $stmt = $db->prepare('UPDATE player_phases SET completed = :c, updated_at = CURRENT_TIMESTAMP WHERE user_id = :u AND phase_number = :p');
            $stmt->execute([':c' => $completed, ':u' => $userId, ':p' => $phaseNumber]);
            echo json_encode(['success' => true]);
            exit;
        }

        echo json_encode(['success' => false]);
        exit;
    }

    echo json_encode(['error' => 'Unbekannte Aktion.']);
    exit;
}

if (isset($_POST['action']) && $_POST['action'] === 'login') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $stmt = $db->prepare('SELECT id, username, display_name, password_hash, role, deposit_cents, color FROM users WHERE username = :u AND role IN ("admin", "player")');
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
            ];
            header('Location: index.php');
            exit;
        }
    }
    $errors[] = 'Anmeldung fehlgeschlagen. Bitte Zugangsdaten prüfen.';
}

if (isset($_POST['action']) && $_POST['action'] === 'guest_login') {
    $code = trim($_POST['guest_code'] ?? '');
    $now = (new DateTimeImmutable('now'))->format(DateTimeInterface::ATOM);
    $stmt = $db->prepare('SELECT id, username, display_name, role, deposit_cents, color, guest_expires_at FROM users WHERE role = "guest" AND guest_code = :c AND guest_expires_at > :now');
    $stmt->execute([':c' => $code, ':now' => $now]);
    if ($user = $stmt->fetch()) {
        $_SESSION['user'] = [
            'id' => $user['id'],
            'username' => $user['username'],
            'display_name' => $user['display_name'],
            'role' => $user['role'],
            'deposit_cents' => $user['deposit_cents'],
            'color' => $user['color'],
            'guest_expires_at' => $user['guest_expires_at'],
        ];
        header('Location: index.php');
        exit;
    }
    $errors[] = 'Gastcode ungültig oder abgelaufen.';
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
            ensurePlayerPhases($db);
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
    $color = trim($_POST['color'] ?? '#25d366');
    $code = trim($_POST['guest_code'] ?? '');

    if (!preg_match('/^\d{4}$/', $code)) {
        $errors[] = 'Gastcode muss aus 4 Ziffern bestehen.';
    } elseif (!$display) {
        $errors[] = 'Bitte einen Namen eingeben.';
    } else {
        $username = 'guest_' . $code . '_' . time();
        $expires = (new DateTimeImmutable('now'))->modify('+24 hours')->format(DateTimeInterface::ATOM);
        $stmt = $db->prepare('INSERT INTO users (username, display_name, password_hash, role, deposit_cents, color, guest_code, guest_expires_at) VALUES (:u, :d, :p, "guest", :dep, :c, :code, :exp)');
        try {
            $stmt->execute([
                ':u' => $username,
                ':d' => $display,
                ':p' => password_hash(bin2hex(random_bytes(8)), PASSWORD_DEFAULT),
                ':dep' => $deposit,
                ':c' => $color,
                ':code' => $code,
                ':exp' => $expires,
            ]);
            ensurePlayerPhases($db);
            $messages[] = 'Gastaccount erstellt (gültig bis ' . $expires . ').';
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
    $color = trim($_POST['color'] ?? '#1f6feb');
    if ($color) {
        $stmt = $db->prepare('UPDATE users SET color = :c WHERE id = :id');
        $stmt->execute([':c' => $color, ':id' => $userId]);
        $messages[] = 'Farbe geändert.';
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

if (isset($_POST['action']) && $_POST['action'] === 'update_phase_meta') {
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
$isLoggedIn = isLoggedIn();
$balances = $isLoggedIn ? getBalances($db) : [];
$phases = getPhases($db);
$scores = $isAdmin ? getScores($db) : [];
$cards = $isLoggedIn ? getCards($db, $isAdmin ? null : (int)currentUser()['id']) : [];
$currentWinner = $balances[0] ?? null;
$usersForAdmin = $isAdmin ? $db->query('SELECT id, display_name FROM users WHERE role IN ("player", "guest") ORDER BY display_name')->fetchAll() : [];
?>
<!doctype html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Phase 10</title>
    <style>
        :root {
            --bg: #0b141a;
            --panel: #111b21;
            --accent: #25d366;
            --text: #e9edef;
            --muted: #8696a0;
            --card-bg: #f5f6f7;
            --shadow: 0 8px 20px rgba(0,0,0,0.15);
        }
        * { box-sizing: border-box; }
        body { margin: 0; font-family: "Segoe UI", system-ui, sans-serif; background: #0b141a; color: var(--text); }
        a { color: inherit; text-decoration: none; }
        .topbar {
            position: fixed; top: 0; left: 0; right: 0;
            background: var(--panel); padding: 1rem 1.25rem; display: flex; justify-content: space-between; align-items: center; z-index: 10;
            border-bottom: 1px solid rgba(255,255,255,0.05);
        }
        .topbar h1 { margin: 0; font-size: 1.2rem; }
        .topbar .status { font-size: 0.85rem; color: var(--muted); }
        .user-meta { text-align: right; font-size: 0.85rem; color: var(--muted); }
        .app-main { padding: 6rem 1rem 5.5rem; min-height: 100vh; }
        .card-panel { background: #1f2c34; border-radius: 16px; padding: 1rem; margin-bottom: 1rem; box-shadow: var(--shadow); }
        .tab-nav {
            position: fixed; bottom: 0; left: 0; right: 0; background: var(--panel);
            display: flex; justify-content: space-around; padding: 0.5rem 0.25rem; border-top: 1px solid rgba(255,255,255,0.05);
        }
        .tab-nav button {
            background: none; border: none; color: var(--muted); font-size: 0.8rem; padding: 0.5rem 1rem;
            display: flex; flex-direction: column; align-items: center; gap: 0.25rem;
        }
        .tab-nav button.active { color: var(--accent); }
        .tab-page { display: none; }
        .tab-page.active { display: block; }
        .login-card { max-width: 420px; margin: 0 auto; background: #ffffff; color: #101418; padding: 1.5rem; border-radius: 16px; box-shadow: var(--shadow); }
        label { display: block; font-size: 0.85rem; margin-top: 0.75rem; color: inherit; }
        input, select, textarea {
            width: 100%; padding: 0.75rem; border-radius: 10px; border: 1px solid #d0d7de; margin-top: 0.35rem; font-size: 1rem;
        }
        button.primary {
            width: 100%; margin-top: 1rem; padding: 0.9rem; border-radius: 999px; border: none; background: var(--accent); color: #082b1d; font-weight: 600; font-size: 1rem;
        }
        .message { color: #52d59a; margin-bottom: 0.5rem; }
        .error { color: #ffb4ab; margin-bottom: 0.5rem; }
        table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
        th, td { padding: 0.6rem; border-bottom: 1px solid rgba(255,255,255,0.08); text-align: left; }
        th { color: var(--muted); font-weight: 500; }
        .phase-list { display: grid; grid-template-columns: 1fr; gap: 0.75rem; }
        .phase-item { padding: 0.75rem; border-radius: 12px; background: #152028; }
        .badge { display: inline-block; padding: 0.2rem 0.6rem; border-radius: 999px; background: rgba(37,211,102,0.2); color: var(--accent); font-size: 0.75rem; margin-bottom: 0.4rem; }
        .cards-container { display: flex; flex-direction: column; gap: 1rem; }
        .phase10-card {
            background: var(--card-bg); color: #111; border-radius: 18px; padding: 1.2rem; min-height: calc(100vh - 14rem); display: flex; flex-direction: column; gap: 1rem; box-shadow: var(--shadow);
            border: 6px solid rgba(0,0,0,0.05);
        }
        .phase10-header { display: flex; justify-content: space-between; align-items: center; }
        .phase10-title { font-size: 1.3rem; font-weight: 700; }
        .phase10-meta { font-size: 0.9rem; color: #344054; }
        .progress-grid { display: grid; grid-template-columns: repeat(2, minmax(0,1fr)); gap: 0.6rem; }
        .progress-item { background: #fff; border-radius: 12px; padding: 0.5rem; display: flex; align-items: center; gap: 0.5rem; border: 1px solid #e2e8f0; }
        .progress-item input { width: 22px; height: 22px; }
        .balance-grid { display: flex; justify-content: space-between; gap: 1rem; }
        .balance-tile { flex: 1; background: #fff; border-radius: 12px; padding: 0.75rem; text-align: center; border: 1px solid #e2e8f0; }
        .balance-tile strong { display: block; font-size: 1.1rem; }
        .admin-section { background: #1f2c34; border-radius: 16px; padding: 1rem; margin-bottom: 1rem; }
        .admin-section h3 { margin-top: 0; }
        .admin-grid { display: grid; grid-template-columns: 1fr; gap: 1rem; }
        .muted { color: var(--muted); font-size: 0.85rem; }
        .winner { margin-top: 0.5rem; color: var(--accent); font-weight: 600; }
        @media (min-width: 768px) {
            .app-main { padding: 6.5rem 2rem 5.5rem; }
            .phase-list { grid-template-columns: repeat(2, minmax(0,1fr)); }
            .admin-grid { grid-template-columns: repeat(2, minmax(0,1fr)); }
            .cards-container { max-width: 720px; margin: 0 auto; }
        }
    </style>
</head>
<body>
<header class="topbar">
    <div>
        <h1>Phase 10</h1>
        <div class="status" id="sync-status">Änderungen werden automatisch gespeichert</div>
        <?php if ($currentWinner && $isLoggedIn): ?>
            <div class="winner">Aktueller Gewinner: <?php echo htmlspecialchars($currentWinner['name']); ?> (<?php echo number_format($currentWinner['remaining'] / 100, 2, ',', '.'); ?> €)</div>
        <?php endif; ?>
    </div>
    <div class="user-meta">
        <?php if ($isLoggedIn): ?>
            <div><?php echo htmlspecialchars(currentUser()['display_name']); ?> (<?php echo htmlspecialchars(currentUser()['role']); ?>)</div>
            <a href="?logout=1">Abmelden</a>
        <?php endif; ?>
    </div>
</header>

<main class="app-main">
    <?php foreach ($messages as $m): ?><div class="message">✔ <?php echo htmlspecialchars($m); ?></div><?php endforeach; ?>
    <?php foreach ($errors as $e): ?><div class="error">⚠ <?php echo htmlspecialchars($e); ?></div><?php endforeach; ?>

    <?php if (!$isLoggedIn): ?>
        <div class="login-card">
            <h2>Login</h2>
            <form method="post">
                <input type="hidden" name="action" value="login">
                <label>Nutzername
                    <input name="username" required>
                </label>
                <label>Passwort
                    <input type="password" name="password" required>
                </label>
                <button type="submit" class="primary">Anmelden</button>
            </form>
            <hr style="margin:1.5rem 0;">
            <h3>Gastzugang</h3>
            <form method="post">
                <input type="hidden" name="action" value="guest_login">
                <label>4-stelliger Code
                    <input name="guest_code" inputmode="numeric" pattern="\d{4}" maxlength="4" required>
                </label>
                <button type="submit" class="primary">Gastlogin</button>
            </form>
        </div>
    <?php else: ?>
        <section class="tab-page active" id="tab-overview" data-tab="overview">
            <div class="card-panel">
                <h2>Rangliste & Guthaben</h2>
                <table>
                    <thead>
                        <tr><th>Platz</th><th>Spieler</th><th>Einzahlung</th><th>Punkte</th><th>Restguthaben</th></tr>
                    </thead>
                    <tbody id="balance-body">
                        <?php foreach ($balances as $index => $row): ?>
                            <tr>
                                <td><?php echo $index + 1; ?></td>
                                <td><?php echo htmlspecialchars($row['name']); ?></td>
                                <td><?php echo number_format($row['deposit'] / 100, 2, ',', '.'); ?> €</td>
                                <td><?php echo $row['points']; ?> Pkt</td>
                                <td><strong><?php echo number_format($row['remaining'] / 100, 2, ',', '.'); ?> €</strong></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>

            <div class="card-panel">
                <h2>Phasen</h2>
                <div class="phase-list">
                    <?php foreach ($phases as $phase): ?>
                        <div class="phase-item">
                            <div class="badge">Phase <?php echo (int)$phase['phase_number']; ?></div>
                            <div><strong><?php echo htmlspecialchars($phase['title']); ?></strong></div>
                            <div class="muted"><?php echo nl2br(htmlspecialchars($phase['info'])); ?></div>
                        </div>
                    <?php endforeach; ?>
                </div>
            </div>
        </section>

        <section class="tab-page" id="tab-cards" data-tab="cards">
            <div class="cards-container" id="cards-container">
                <?php foreach ($cards as $card): ?>
                    <div class="phase10-card" style="border-color: <?php echo htmlspecialchars($card['color']); ?>">
                        <div class="phase10-header">
                            <div>
                                <div class="phase10-title" style="color: <?php echo htmlspecialchars($card['color']); ?>"><?php echo htmlspecialchars($card['name']); ?></div>
                                <div class="phase10-meta">Phase-10-Karte</div>
                            </div>
                            <div class="phase10-meta">Farbe: <?php echo htmlspecialchars($card['color']); ?></div>
                        </div>
                        <div class="balance-grid">
                            <div class="balance-tile">Guthaben<strong><?php echo number_format($card['deposit'] / 100, 2, ',', '.'); ?> €</strong></div>
                            <div class="balance-tile">Punkte<strong><?php echo $card['points']; ?></strong></div>
                            <div class="balance-tile">Rest<strong class="js-remaining" data-user="<?php echo $card['id']; ?>"><?php echo number_format($card['remaining'] / 100, 2, ',', '.'); ?> €</strong></div>
                        </div>
                        <div class="progress-grid">
                            <?php foreach ($card['phases'] as $phase): ?>
                                <label class="progress-item">
                                    <input type="checkbox" class="phase-checkbox" data-user="<?php echo $card['id']; ?>" data-phase="<?php echo $phase['phase_number']; ?>" <?php echo $phase['completed'] ? 'checked' : ''; ?>>
                                    <span>Phase <?php echo $phase['phase_number']; ?></span>
                                </label>
                            <?php endforeach; ?>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        </section>

        <?php if ($isAdmin): ?>
            <section class="tab-page" id="tab-admin" data-tab="admin">
                <div class="admin-section">
                    <h2>Admin: Spieler & Gäste</h2>
                    <div class="admin-grid">
                        <form method="post" class="card-panel" style="background:#162026;">
                            <input type="hidden" name="action" value="create_user">
                            <h3>Neuen Account anlegen</h3>
                            <label>Nutzername<input name="username" required></label>
                            <label>Anzeigename<input name="display_name" required></label>
                            <label>Passwort<input type="password" name="password" required></label>
                            <label>Farbe<input type="color" name="color" value="#1f6feb" required></label>
                            <label>Rolle
                                <select name="role">
                                    <option value="player">Spieler</option>
                                    <option value="admin">Admin</option>
                                </select>
                            </label>
                            <button type="submit" class="primary">Speichern</button>
                        </form>

                        <form method="post" class="card-panel" style="background:#162026;">
                            <input type="hidden" name="action" value="create_guest">
                            <h3>Gastaccount erstellen</h3>
                            <label>Name<input name="display_name" required></label>
                            <label>Startguthaben (€)<input type="number" name="deposit_euro" step="0.01" min="0" required></label>
                            <label>Farbe<input type="color" name="color" value="#25d366" required></label>
                            <label>4-stelliger Code<input name="guest_code" inputmode="numeric" pattern="\d{4}" maxlength="4" required></label>
                            <button type="submit" class="primary">Gast anlegen</button>
                            <div class="muted">Gültig für 24 Stunden ab Erstellung.</div>
                        </form>
                    </div>
                </div>

                <div class="admin-section">
                    <h2>Admin: Spieler verwalten</h2>
                    <div class="admin-grid">
                        <form method="post" class="card-panel" style="background:#162026;">
                            <input type="hidden" name="action" value="update_password">
                            <h3>Passwort ändern</h3>
                            <label>Spieler
                                <select name="user_id">
                                    <?php foreach ($usersForAdmin as $row): ?>
                                        <option value="<?php echo $row['id']; ?>"><?php echo htmlspecialchars($row['display_name']); ?></option>
                                    <?php endforeach; ?>
                                </select>
                            </label>
                            <label>Neues Passwort<input type="password" name="password" required></label>
                            <button type="submit" class="primary">Aktualisieren</button>
                        </form>

                        <form method="post" class="card-panel" style="background:#162026;">
                            <input type="hidden" name="action" value="rename_user">
                            <h3>Name ändern</h3>
                            <label>Spieler
                                <select name="user_id">
                                    <?php foreach ($usersForAdmin as $row): ?>
                                        <option value="<?php echo $row['id']; ?>"><?php echo htmlspecialchars($row['display_name']); ?></option>
                                    <?php endforeach; ?>
                                </select>
                            </label>
                            <label>Neuer Anzeigename<input name="display_name" required></label>
                            <button type="submit" class="primary">Speichern</button>
                        </form>

                        <form method="post" class="card-panel" style="background:#162026;">
                            <input type="hidden" name="action" value="update_color">
                            <h3>Farbe ändern</h3>
                            <label>Spieler
                                <select name="user_id">
                                    <?php foreach ($usersForAdmin as $row): ?>
                                        <option value="<?php echo $row['id']; ?>"><?php echo htmlspecialchars($row['display_name']); ?></option>
                                    <?php endforeach; ?>
                                </select>
                            </label>
                            <label>Neue Farbe<input type="color" name="color" value="#1f6feb" required></label>
                            <button type="submit" class="primary">Speichern</button>
                        </form>
                    </div>
                </div>

                <div class="admin-section">
                    <h2>Admin: Einzahlungen & Punkte</h2>
                    <div class="admin-grid">
                        <form method="post" class="card-panel" style="background:#162026;">
                            <input type="hidden" name="action" value="update_deposit">
                            <h3>Einzahlung hinterlegen</h3>
                            <label>Spieler
                                <select name="user_id">
                                    <?php foreach ($usersForAdmin as $row): ?>
                                        <option value="<?php echo $row['id']; ?>"><?php echo htmlspecialchars($row['display_name']); ?></option>
                                    <?php endforeach; ?>
                                </select>
                            </label>
                            <label>Einzahlung (€)
                                <input type="number" name="deposit_euro" step="0.01" min="0" required>
                            </label>
                            <button type="submit" class="primary">Speichern</button>
                        </form>

                        <form method="post" class="card-panel" style="background:#162026;">
                            <input type="hidden" name="action" value="add_score">
                            <h3>Punkte eintragen</h3>
                            <label>Spieler
                                <select name="user_id">
                                    <?php foreach ($usersForAdmin as $row): ?>
                                        <option value="<?php echo $row['id']; ?>"><?php echo htmlspecialchars($row['display_name']); ?></option>
                                    <?php endforeach; ?>
                                </select>
                            </label>
                            <label>Runde
                                <input type="number" name="round_number" min="1" value="1" required>
                            </label>
                            <label>Punkte (1 Punkt = 1 Cent)
                                <input type="number" name="points" step="1" required>
                            </label>
                            <button type="submit" class="primary">Speichern</button>
                        </form>
                    </div>

                    <h3>Letzte Punktänderungen</h3>
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
                                        <button type="submit" class="primary" style="width:auto; padding:0.5rem 1rem;">Aktualisieren</button>
                                    </form>
                                    <form method="post">
                                        <input type="hidden" name="score_id" value="<?php echo $score['id']; ?>">
                                        <input type="hidden" name="action" value="delete_score">
                                        <button type="submit" class="primary" style="width:auto; padding:0.5rem 1rem; background:#e5484d; color:white;">Löschen</button>
                                    </form>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>

                <div class="admin-section">
                    <h2>Admin: Phasenverwaltung</h2>
                    <div class="admin-grid">
                    <?php foreach ($phases as $phase): ?>
                        <form method="post" class="card-panel" style="background:#162026;">
                            <input type="hidden" name="action" value="update_phase_meta">
                            <input type="hidden" name="phase_number" value="<?php echo $phase['phase_number']; ?>">
                            <div class="badge">Phase <?php echo $phase['phase_number']; ?></div>
                            <label>Titel
                                <input name="title" value="<?php echo htmlspecialchars($phase['title']); ?>" required>
                            </label>
                            <label>Info
                                <textarea name="info" rows="3"><?php echo htmlspecialchars($phase['info']); ?></textarea>
                            </label>
                            <button type="submit" class="primary">Speichern</button>
                        </form>
                    <?php endforeach; ?>
                    </div>
                </div>
            </section>
        <?php endif; ?>
    <?php endif; ?>
</main>

<?php if ($isLoggedIn): ?>
<nav class="tab-nav">
    <button data-tab-target="overview" class="active">Übersicht</button>
    <button data-tab-target="cards">Karten</button>
    <?php if ($isAdmin): ?>
        <button data-tab-target="admin">Admin</button>
    <?php endif; ?>
</nav>
<?php endif; ?>

<?php if ($isLoggedIn): ?>
<script>
    const tabs = document.querySelectorAll('.tab-nav button');
    const pages = document.querySelectorAll('.tab-page');
    const syncStatus = document.getElementById('sync-status');

    function switchTab(target) {
        tabs.forEach(btn => btn.classList.toggle('active', btn.dataset.tabTarget === target));
        pages.forEach(page => page.classList.toggle('active', page.dataset.tab === target));
    }

    tabs.forEach(btn => {
        btn.addEventListener('click', () => switchTab(btn.dataset.tabTarget));
    });

    async function postPhaseUpdate(checkbox) {
        const data = new URLSearchParams();
        data.append('user_id', checkbox.dataset.user);
        data.append('phase_number', checkbox.dataset.phase);
        data.append('completed', checkbox.checked ? '1' : '0');
        syncStatus.textContent = 'Speichere…';
        const response = await fetch('index.php?ajax=update_phase', {
            method: 'POST',
            headers: {'Content-Type': 'application/x-www-form-urlencoded'},
            body: data
        });
        const result = await response.json();
        syncStatus.textContent = result.success ? 'Änderungen werden automatisch gespeichert' : 'Speichern fehlgeschlagen';
    }

    document.addEventListener('change', (event) => {
        if (event.target.classList.contains('phase-checkbox')) {
            postPhaseUpdate(event.target).catch(() => {
                syncStatus.textContent = 'Speichern fehlgeschlagen';
            });
        }
    });

    function renderBalances(balances) {
        const tbody = document.getElementById('balance-body');
        if (!tbody) return;
        tbody.innerHTML = '';
        balances.forEach((row, index) => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${index + 1}</td>
                <td>${row.name}</td>
                <td>${(row.deposit / 100).toFixed(2).replace('.', ',')} €</td>
                <td>${row.points} Pkt</td>
                <td><strong>${(row.remaining / 100).toFixed(2).replace('.', ',')} €</strong></td>
            `;
            tbody.appendChild(tr);
        });
    }

    function renderCards(cards) {
        const container = document.getElementById('cards-container');
        if (!container) return;
        container.innerHTML = '';
        cards.forEach(card => {
            const wrapper = document.createElement('div');
            wrapper.className = 'phase10-card';
            wrapper.style.borderColor = card.color;
            wrapper.innerHTML = `
                <div class="phase10-header">
                    <div>
                        <div class="phase10-title" style="color:${card.color}">${card.name}</div>
                        <div class="phase10-meta">Phase-10-Karte</div>
                    </div>
                    <div class="phase10-meta">Farbe: ${card.color}</div>
                </div>
                <div class="balance-grid">
                    <div class="balance-tile">Guthaben<strong>${(card.deposit / 100).toFixed(2).replace('.', ',')} €</strong></div>
                    <div class="balance-tile">Punkte<strong>${card.points}</strong></div>
                    <div class="balance-tile">Rest<strong class="js-remaining" data-user="${card.id}">${(card.remaining / 100).toFixed(2).replace('.', ',')} €</strong></div>
                </div>
                <div class="progress-grid">
                    ${card.phases.map(phase => `
                        <label class="progress-item">
                            <input type="checkbox" class="phase-checkbox" data-user="${card.id}" data-phase="${phase.phase_number}" ${phase.completed ? 'checked' : ''}>
                            <span>Phase ${phase.phase_number}</span>
                        </label>
                    `).join('')}
                </div>
            `;
            container.appendChild(wrapper);
        });
    }

    function renderScores(scores) {
        const tbody = document.getElementById('scores-body');
        if (!tbody) return;
        tbody.innerHTML = '';
        scores.forEach(score => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
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
                        <button type="submit" class="primary" style="width:auto; padding:0.5rem 1rem;">Aktualisieren</button>
                    </form>
                    <form method="post">
                        <input type="hidden" name="score_id" value="${score.id}">
                        <input type="hidden" name="action" value="delete_score">
                        <button type="submit" class="primary" style="width:auto; padding:0.5rem 1rem; background:#e5484d; color:white;">Löschen</button>
                    </form>
                </td>
            `;
            tbody.appendChild(tr);
        });
    }

    async function pollState() {
        try {
            const response = await fetch('index.php?ajax=state');
            const data = await response.json();
            if (!data.logged_in) {
                return;
            }
            renderBalances(data.balances || []);
            renderCards(data.cards || []);
            if (data.is_admin) {
                renderScores(data.scores || []);
            }
            syncStatus.textContent = 'Änderungen werden automatisch gespeichert';
        } catch (err) {
            syncStatus.textContent = 'Sync fehlgeschlagen';
        }
    }

    setInterval(pollState, 5000);
</script>
<?php endif; ?>
</body>
</html>
