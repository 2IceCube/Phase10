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

function refreshUser(PDO $db): void
{
    if (!isLoggedIn()) {
        return;
    }
    $stmt = $db->prepare('SELECT id, username, display_name, role, deposit_cents FROM users WHERE id = :id');
    $stmt->execute([':id' => $_SESSION['user']['id']]);
    if ($row = $stmt->fetch()) {
        $_SESSION['user'] = $row;
    }
}

function requireAdmin(): void
{
    if (!isLoggedIn() || $_SESSION['user']['role'] !== 'admin') {
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

function getBalances(PDO $db): array
{
    $stmt = $db->query('SELECT id, display_name, deposit_cents FROM users ORDER BY display_name');
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

function getScores(PDO $db, int $limit = 30): array
{
    $stmt = $db->prepare('SELECT s.id, s.round_number, s.points, s.created_at, u.display_name FROM scores s JOIN users u ON u.id = s.user_id ORDER BY s.round_number DESC, s.id DESC LIMIT :lim');
    $stmt->bindValue(':lim', $limit, PDO::PARAM_INT);
    $stmt->execute();
    return $stmt->fetchAll();
}

if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: index.php');
    exit;
}

if (isset($_POST['action']) && $_POST['action'] === 'login') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $stmt = $db->prepare('SELECT id, username, display_name, password_hash, role, deposit_cents FROM users WHERE username = :u');
    $stmt->execute([':u' => $username]);
    if ($user = $stmt->fetch()) {
        if (password_verify($password, $user['password_hash'])) {
            $_SESSION['user'] = [
                'id' => $user['id'],
                'username' => $user['username'],
                'display_name' => $user['display_name'],
                'role' => $user['role'],
                'deposit_cents' => $user['deposit_cents'],
            ];
            header('Location: index.php');
            exit;
        }
    }
    $errors[] = 'Anmeldung fehlgeschlagen. Bitte Zugangsdaten prüfen.';
}

if (isset($_POST['action']) && $_POST['action'] === 'guest_login') {
    $code = trim($_POST['guest_code'] ?? '');
    $expected = getSetting($db, 'guest_code', '1234');
    if (preg_match('/^\d{4}$/', $code) && $code === $expected) {
        $_SESSION['guest'] = true;
        $messages[] = 'Gastzugang aktiv.';
    } else {
        $errors[] = 'Gastcode ungültig. Bitte den 4-stelligen Code beim Admin erfragen.';
    }
}

if (isset($_POST['action']) && $_POST['action'] === 'create_user') {
    requireAdmin();
    $username = trim($_POST['username'] ?? '');
    $display = trim($_POST['display_name'] ?? '');
    $password = $_POST['password'] ?? '';
    $role = $_POST['role'] === 'admin' ? 'admin' : 'player';
    if ($username && $display && $password) {
        $stmt = $db->prepare('INSERT INTO users (username, display_name, password_hash, role) VALUES (:u, :d, :p, :r)');
        try {
            $stmt->execute([
                ':u' => $username,
                ':d' => $display,
                ':p' => password_hash($password, PASSWORD_DEFAULT),
                ':r' => $role,
            ]);
            $messages[] = 'Nutzer wurde angelegt.';
        } catch (PDOException $e) {
            $errors[] = 'Fehler beim Anlegen: ' . htmlspecialchars($e->getMessage());
        }
    } else {
        $errors[] = 'Bitte alle Felder ausfüllen (Nutzername, Anzeigename, Passwort).';
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

if (isset($_POST['action']) && $_POST['action'] === 'update_guest_code') {
    requireAdmin();
    $code = trim($_POST['guest_code'] ?? '');
    if (preg_match('/^\d{4}$/', $code)) {
        setSetting($db, 'guest_code', $code);
        $messages[] = 'Gastcode aktualisiert.';
    } else {
        $errors[] = 'Gastcode muss 4-stellig und numerisch sein.';
    }
}

refreshUser($db);

$isAdmin = isLoggedIn() && currentUser()['role'] === 'admin';
$balances = getBalances($db);
$phases = getPhases($db);
$scores = getScores($db);
$currentWinner = $balances[0] ?? null;
$guestCode = getSetting($db, 'guest_code', '1234');

$initialTab = 'overview';
if ($isAdmin) {
    $initialTab = 'admin-game';
} elseif (isLoggedIn()) {
    $initialTab = 'player';
} elseif (isset($_SESSION['guest'])) {
    $initialTab = 'guest';
} else {
    $initialTab = 'login';
}
?>
<!doctype html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Phase 10 Verwaltung (PHP & SQLite)</title>
    <style>
        :root {
            color-scheme: dark;
            --bg: #0b1220;
            --surface: #111a2e;
            --surface-soft: #0f1629;
            --accent: #62d0ff;
            --accent-strong: #7af5c9;
            --text: #e5ecff;
            --muted: #98a7c2;
            --border: #1f2a44;
            --danger: #ff6b6b;
            --success: #80ffea;
        }

        * { box-sizing: border-box; }
        body {
            margin: 0;
            font-family: 'Inter', system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: radial-gradient(circle at 20% 20%, rgba(98, 208, 255, 0.08), transparent 35%),
                        radial-gradient(circle at 80% 0%, rgba(122, 245, 201, 0.08), transparent 30%),
                        var(--bg);
            color: var(--text);
            min-height: 100vh;
        }
        header {
            padding: 1.25rem 1.5rem 0.75rem;
            display: flex;
            gap: 1.5rem;
            justify-content: space-between;
            align-items: center;
            position: sticky;
            top: 0;
            backdrop-filter: blur(10px);
            background: linear-gradient(180deg, rgba(11, 18, 32, 0.9), rgba(11, 18, 32, 0.6));
            z-index: 10;
        }
        h1 {
            margin: 0 0 .25rem;
            font-weight: 700;
            letter-spacing: -0.02em;
        }
        .subtitle { color: var(--muted); margin: 0; }
        .card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 1.25rem;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.35);
        }
        .grid { display: grid; gap: 1rem; }
        .grid.two { grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); }
        .grid.three { grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); }
        .top-bar {
            display: flex;
            align-items: center;
            gap: 1rem;
            flex-wrap: wrap;
        }
        .badge {
            display: inline-flex;
            align-items: center;
            gap: .35rem;
            padding: .35rem .65rem;
            border-radius: 999px;
            background: rgba(98, 208, 255, 0.12);
            color: var(--accent);
            font-weight: 600;
            font-size: .9rem;
        }
        .tag-success { background: rgba(122, 245, 201, 0.12); color: var(--accent-strong); }
        .tag-danger { background: rgba(255, 107, 107, 0.12); color: var(--danger); }
        .nav {
            display: flex;
            gap: .5rem;
            flex-wrap: wrap;
            padding: 0 1.5rem 1rem;
        }
        .tab-btn {
            padding: .65rem 1rem;
            border-radius: 10px;
            border: 1px solid var(--border);
            background: var(--surface-soft);
            color: var(--text);
            cursor: pointer;
            transition: all .15s ease;
        }
        .tab-btn.active { border-color: var(--accent); box-shadow: 0 6px 18px rgba(98, 208, 255, 0.15); }
        .tab-btn:hover { transform: translateY(-1px); }
        .section { display: none; padding: 0 1.5rem 1.5rem; }
        .section.active { display: block; }
        form { display: grid; gap: .75rem; }
        label { font-weight: 600; color: var(--muted); display: block; }
        input, select, textarea, button {
            width: 100%;
            padding: .65rem .75rem;
            border-radius: 10px;
            border: 1px solid var(--border);
            background: var(--surface-soft);
            color: var(--text);
            font-size: 1rem;
        }
        input:focus, select:focus, textarea:focus { outline: 2px solid rgba(98, 208, 255, 0.4); }
        button { cursor: pointer; background: linear-gradient(120deg, var(--accent), var(--accent-strong)); color: #0b1220; font-weight: 700; border: none; }
        table { width: 100%; border-collapse: collapse; color: var(--text); }
        th, td { padding: .65rem; border-bottom: 1px solid var(--border); text-align: left; }
        th { color: var(--muted); font-weight: 600; }
        tr:hover { background: rgba(255,255,255,0.02); }
        .message { color: var(--success); margin: .25rem 1.5rem; }
        .error { color: var(--danger); margin: .25rem 1.5rem; }
        .pill { padding: .35rem .55rem; border-radius: 8px; background: rgba(255,255,255,0.04); font-weight: 600; }
        .stack { display: grid; gap: .5rem; }
        .flex { display: flex; gap: .75rem; align-items: center; flex-wrap: wrap; }
        @media (max-width: 720px) {
            header { flex-direction: column; align-items: flex-start; position: static; }
        }
    </style>
</head>
<body>
<header>
    <div>
        <h1>Phase 10 Punkte & Guthaben</h1>
        <p class="subtitle">Modernes Darkmode-Board für Spieler, Gäste & Admins</p>
    </div>
    <div class="stack" style="text-align:right;">
        <?php if ($currentWinner): ?>
            <span class="badge tag-success">Aktueller Gewinner: <strong><?php echo htmlspecialchars($currentWinner['name']); ?></strong> · Auszahlung <?php echo number_format($currentWinner['remaining']/100, 2, ',', '.'); ?> €</span>
        <?php endif; ?>
        <div class="flex" style="justify-content:flex-end;">
            <?php if (isLoggedIn()): ?>
                <span class="pill">Angemeldet als <?php echo htmlspecialchars(currentUser()['display_name']); ?> (<?php echo htmlspecialchars(currentUser()['role']); ?>)</span>
                <a class="pill" href="?logout=1" style="text-decoration:none;">Abmelden</a>
            <?php elseif (isset($_SESSION['guest'])): ?>
                <span class="pill">Gastmodus aktiv</span>
                <a class="pill" href="?logout=1" style="text-decoration:none;">Beenden</a>
            <?php else: ?>
                <span class="pill">Nicht angemeldet</span>
            <?php endif; ?>
        </div>
    </div>
</header>

<?php foreach ($messages as $m): ?><div class="message">✔ <?php echo htmlspecialchars($m); ?></div><?php endforeach; ?>
<?php foreach ($errors as $e): ?><div class="error">⚠ <?php echo htmlspecialchars($e); ?></div><?php endforeach; ?>

<nav class="nav">
    <button class="tab-btn" data-tab="overview">Übersicht</button>
    <?php if (!isLoggedIn() && !isset($_SESSION['guest'])): ?>
        <button class="tab-btn" data-tab="login">Login</button>
        <button class="tab-btn" data-tab="guest">Gast</button>
    <?php endif; ?>
    <?php if (isset($_SESSION['guest'])): ?>
        <button class="tab-btn" data-tab="guest">Gast</button>
    <?php endif; ?>
    <?php if (isLoggedIn() && currentUser()['role'] === 'player'): ?>
        <button class="tab-btn" data-tab="player">Spieler</button>
    <?php endif; ?>
    <?php if ($isAdmin): ?>
        <button class="tab-btn" data-tab="admin-users">Admin · Zugänge</button>
        <button class="tab-btn" data-tab="admin-game">Admin · Spiel</button>
        <button class="tab-btn" data-tab="admin-phases">Admin · Phasen</button>
    <?php endif; ?>
</nav>

<section class="section" data-tab="overview">
    <div class="grid two">
        <div class="card">
            <div class="top-bar">
                <h2 style="margin:0;">Rangliste & Guthaben</h2>
                <span class="badge">1 Punkt = 1 Cent</span>
            </div>
            <div style="overflow-x:auto;">
                <table>
                    <thead>
                    <tr><th>Platz</th><th>Spieler</th><th>Einzahlung</th><th>Punkte</th><th>Restguthaben</th></tr>
                    </thead>
                    <tbody>
                    <?php foreach ($balances as $index => $row): ?>
                        <tr>
                            <td><?php echo $index + 1; ?></td>
                            <td><?php echo htmlspecialchars($row['name']); ?></td>
                            <td><?php echo number_format($row['deposit']/100, 2, ',', '.'); ?> €</td>
                            <td><?php echo $row['points']; ?> Pkt</td>
                            <td><strong><?php echo number_format($row['remaining']/100, 2, ',', '.'); ?> €</strong></td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
        <div class="card">
            <div class="top-bar">
                <h2 style="margin:0;">Phasenübersicht</h2>
                <span class="badge">Individuell pro Phase</span>
            </div>
            <div class="grid three">
                <?php foreach ($phases as $phase): ?>
                    <div class="card" style="background:var(--surface-soft); border-color:var(--border);">
                        <div class="badge">Phase <?php echo (int)$phase['phase_number']; ?></div>
                        <div style="font-weight:700; margin:.35rem 0;"><?php echo htmlspecialchars($phase['title']); ?></div>
                        <div style="color:var(--muted); white-space:pre-wrap;"><?php echo htmlspecialchars($phase['info']); ?></div>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>
    </div>
</section>

<section class="section" data-tab="login">
    <div class="grid two">
        <div class="card">
            <h2>Anmeldung</h2>
            <form method="post" class="grid">
                <input type="hidden" name="action" value="login">
                <label>Nutzername
                    <input name="username" required autocomplete="username">
                </label>
                <label>Passwort
                    <input type="password" name="password" required autocomplete="current-password">
                </label>
                <button type="submit">Anmelden</button>
            </form>
        </div>
        <div class="card" style="background:var(--surface-soft);">
            <h3>Gastcode beim Admin holen</h3>
            <p class="subtitle">Admins vergeben einen 4-stelligen Code, damit Gäste beitreten können.</p>
            <div class="badge">Sicherer Zugang</div>
        </div>
    </div>
</section>

<section class="section" data-tab="guest">
    <div class="grid two">
        <div class="card">
            <h2>Gast beitreten</h2>
            <form method="post">
                <input type="hidden" name="action" value="guest_login">
                <label>4-stelliger Gastcode
                    <input name="guest_code" pattern="\d{4}" minlength="4" maxlength="4" required placeholder="z.B. 1234">
                </label>
                <button type="submit">Gastmodus starten</button>
            </form>
            <?php if (isset($_SESSION['guest'])): ?>
                <p class="subtitle" style="margin-top:.75rem;">Gastmodus aktiv – du kannst die Übersicht und Phasen einsehen.</p>
            <?php endif; ?>
        </div>
        <div class="card" style="background:var(--surface-soft);">
            <h3>Was sehe ich als Gast?</h3>
            <ul style="color:var(--muted); line-height:1.6;">
                <li>Aktuelle Rangliste & Auszahlungen</li>
                <li>Alle Phasen inkl. Info-Spalte</li>
                <li>Kein Zugriff auf Admin-Funktionen</li>
            </ul>
        </div>
    </div>
</section>

<?php if (isLoggedIn() && currentUser()['role'] === 'player'): ?>
<section class="section" data-tab="player">
    <?php $user = currentUser(); $points = sumPoints($db, (int)$user['id']); $remaining = (int)$user['deposit_cents'] - $points; ?>
    <div class="grid two">
        <div class="card">
            <div class="top-bar">
                <h2 style="margin:0;">Dein Konto</h2>
                <span class="badge">Live-Stand</span>
            </div>
            <p>Guthaben: <strong><?php echo number_format($user['deposit_cents']/100, 2, ',', '.'); ?> €</strong></p>
            <p>Punkte: <?php echo $points; ?> (<?php echo number_format($points/100, 2, ',', '.'); ?> € Abzug)</p>
            <p>Rest: <strong><?php echo number_format($remaining/100, 2, ',', '.'); ?> €</strong></p>
        </div>
        <div class="card" style="background:var(--surface-soft);">
            <h3>Hinweis</h3>
            <p class="subtitle">Dein Admin kann Punkte im Nachhinein korrigieren und Einzahlungen anpassen.</p>
        </div>
    </div>
</section>
<?php endif; ?>

<?php if ($isAdmin): ?>
<section class="section" data-tab="admin-users">
    <div class="grid three">
        <div class="card">
            <h2>Account anlegen</h2>
            <form method="post">
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
                <button type="submit">Speichern</button>
            </form>
        </div>

        <div class="card">
            <h2>Zugangsdaten ändern</h2>
            <form method="post">
                <input type="hidden" name="action" value="update_password">
                <label>Account
                    <select name="user_id">
                        <?php foreach ($balances as $row): ?>
                            <option value="<?php echo $row['id']; ?>"><?php echo htmlspecialchars($row['name']); ?></option>
                        <?php endforeach; ?>
                    </select>
                </label>
                <label>Neues Passwort<input type="password" name="password" required></label>
                <button type="submit">Aktualisieren</button>
            </form>
        </div>

        <div class="card">
            <h2>Namen ändern</h2>
            <form method="post">
                <input type="hidden" name="action" value="rename_user">
                <label>Account
                    <select name="user_id">
                        <?php foreach ($balances as $row): ?>
                            <option value="<?php echo $row['id']; ?>"><?php echo htmlspecialchars($row['name']); ?></option>
                        <?php endforeach; ?>
                    </select>
                </label>
                <label>Neuer Anzeigename<input name="display_name" required></label>
                <button type="submit">Speichern</button>
            </form>
        </div>
    </div>
</section>

<section class="section" data-tab="admin-game">
    <div class="grid two">
        <div class="card">
            <h2>Einzahlungen & Gastcode</h2>
            <form method="post">
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
            <hr style="border:1px solid var(--border); margin:1rem 0;">
            <form method="post">
                <input type="hidden" name="action" value="update_guest_code">
                <label>Gastcode (4 Ziffern)
                    <input name="guest_code" pattern="\d{4}" minlength="4" maxlength="4" value="<?php echo htmlspecialchars($guestCode); ?>" required>
                </label>
                <button type="submit">Gastcode aktualisieren</button>
            </form>
        </div>
        <div class="card">
            <h2>Punkte eintragen</h2>
            <form method="post">
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
                <button type="submit">Speichern</button>
            </form>
        </div>
    </div>

    <div class="card" style="margin-top:1rem;">
        <div class="top-bar">
            <h2 style="margin:0;">Letzte Punktänderungen</h2>
            <span class="badge">Bearbeitbar</span>
        </div>
        <div style="overflow-x:auto;">
            <table>
                <thead><tr><th>Spieler</th><th>Runde</th><th>Punkte</th><th>Datum</th><th>Aktion</th></tr></thead>
                <tbody>
                <?php foreach ($scores as $score): ?>
                    <tr>
                        <td><?php echo htmlspecialchars($score['display_name']); ?></td>
                        <td><?php echo (int)$score['round_number']; ?></td>
                        <td><?php echo (int)$score['points']; ?></td>
                        <td><?php echo htmlspecialchars($score['created_at']); ?></td>
                        <td>
                            <form method="post" class="flex" style="margin-bottom:.35rem;">
                                <input type="hidden" name="score_id" value="<?php echo $score['id']; ?>">
                                <input type="hidden" name="action" value="update_score">
                                <input type="number" name="round_number" value="<?php echo $score['round_number']; ?>" min="1" style="width:90px;">
                                <input type="number" name="points" value="<?php echo $score['points']; ?>" style="width:90px;">
                                <button type="submit">Aktualisieren</button>
                            </form>
                            <form method="post" onsubmit="return confirm('Eintrag löschen?');">
                                <input type="hidden" name="score_id" value="<?php echo $score['id']; ?>">
                                <input type="hidden" name="action" value="delete_score">
                                <button type="submit" style="background: var(--danger); color: #0b1220;">Löschen</button>
                            </form>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
</section>

<section class="section" data-tab="admin-phases">
    <div class="grid two">
    <?php foreach ($phases as $phase): ?>
        <div class="card">
            <form method="post" class="grid">
                <input type="hidden" name="action" value="update_phase">
                <input type="hidden" name="phase_number" value="<?php echo $phase['phase_number']; ?>">
                <div class="badge">Phase <?php echo $phase['phase_number']; ?></div>
                <label>Titel
                    <input name="title" value="<?php echo htmlspecialchars($phase['title']); ?>" required>
                </label>
                <label>Info
                    <textarea name="info" rows="3"><?php echo htmlspecialchars($phase['info']); ?></textarea>
                </label>
                <button type="submit">Speichern</button>
            </form>
        </div>
    <?php endforeach; ?>
    </div>
</section>
<?php endif; ?>

<script>
    const buttons = document.querySelectorAll('.tab-btn');
    const sections = document.querySelectorAll('.section');
    const initial = '<?php echo $initialTab; ?>';

    function activate(tab) {
        buttons.forEach(btn => btn.classList.toggle('active', btn.dataset.tab === tab));
        sections.forEach(sec => sec.classList.toggle('active', sec.dataset.tab === tab));
        window.location.hash = tab;
    }

    buttons.forEach(btn => {
        btn.addEventListener('click', () => activate(btn.dataset.tab));
    });

    const hashTab = window.location.hash.replace('#', '');
    const startTab = Array.from(buttons).some(b => b.dataset.tab === hashTab) ? hashTab : initial;
    activate(startTab);
</script>
</body>
</html>
