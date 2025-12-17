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

if (isset($_POST['action']) && $_POST['action'] === 'guest') {
    $_SESSION['guest'] = true;
    header('Location: index.php');
    exit;
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

refreshUser($db);

$isAdmin = isLoggedIn() && currentUser()['role'] === 'admin';
$balances = getBalances($db);
$phases = getPhases($db);
$scores = getScores($db);
$currentWinner = $balances[0] ?? null;
?>
<!doctype html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Phase 10 Verwaltung (PHP & SQLite)</title>
    <style>
        body { font-family: system-ui, sans-serif; margin: 0; padding: 1rem; background:#f4f6f8; }
        header { display:flex; justify-content:space-between; align-items:center; }
        section { background: white; margin: 1rem 0; padding: 1rem; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
        h2 { margin-top:0; }
        form { margin-bottom: .5rem; }
        label { display:block; font-size: .9rem; margin-top:.25rem; }
        input, select, button, textarea { padding: .5rem; margin-top:.25rem; width: 100%; max-width: 320px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: .5rem; text-align: left; }
        th { background:#eef2f6; }
        .flex { display:flex; gap:1rem; flex-wrap:wrap; }
        .badge { display:inline-block; padding: .25rem .5rem; background:#1f6feb; color:white; border-radius:4px; font-size:.8rem; }
        .error { color: #b3261e; }
        .message { color: #0b6e4f; }
    </style>
</head>
<body>
<header>
    <div>
        <h1>Phase 10 Punkte & Guthaben</h1>
        <?php if ($currentWinner): ?>
            <div>Aktueller Gewinner: <strong><?php echo htmlspecialchars($currentWinner['name']); ?></strong> (Auszahlung: <?php echo number_format($currentWinner['remaining']/100, 2, ',', '.'); ?> €)</div>
        <?php endif; ?>
    </div>
    <div>
        <?php if (isLoggedIn()): ?>
            <div>Angemeldet als <strong><?php echo htmlspecialchars(currentUser()['display_name']); ?></strong> (<?php echo htmlspecialchars(currentUser()['role']); ?>)</div>
            <a href="?logout=1">Abmelden</a>
        <?php elseif (isset($_SESSION['guest'])): ?>
            <div>Gastmodus aktiv</div>
            <a href="?logout=1">Beenden</a>
        <?php endif; ?>
    </div>
</header>

<?php foreach ($messages as $m): ?><div class="message">✔ <?php echo htmlspecialchars($m); ?></div><?php endforeach; ?>
<?php foreach ($errors as $e): ?><div class="error">⚠ <?php echo htmlspecialchars($e); ?></div><?php endforeach; ?>

<?php if (!isLoggedIn() && !isset($_SESSION['guest'])): ?>
    <section>
        <h2>Anmeldung</h2>
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
        <form method="post" style="margin-top:.5rem;">
            <input type="hidden" name="action" value="guest">
            <button type="submit">Gastmodus anzeigen</button>
        </form>
    </section>
<?php endif; ?>

<section>
    <h2>Rangliste & Guthaben</h2>
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
</section>

<section>
    <h2>Phasen</h2>
    <div class="flex">
        <?php foreach ($phases as $phase): ?>
            <div style="min-width: 220px;">
                <div class="badge">Phase <?php echo (int)$phase['phase_number']; ?></div>
                <div><strong><?php echo htmlspecialchars($phase['title']); ?></strong></div>
                <div><?php echo nl2br(htmlspecialchars($phase['info'])); ?></div>
            </div>
        <?php endforeach; ?>
    </div>
</section>

<?php if (isLoggedIn() && currentUser()['role'] === 'player'): ?>
    <?php $user = currentUser(); $points = sumPoints($db, (int)$user['id']); $remaining = (int)$user['deposit_cents'] - $points; ?>
    <section>
        <h2>Dein Konto</h2>
        <p>Guthaben: <?php echo number_format($user['deposit_cents']/100, 2, ',', '.'); ?> €</p>
        <p>Punkte: <?php echo $points; ?> (<?php echo number_format($points/100, 2, ',', '.'); ?> € Abzug)</p>
        <p>Rest: <strong><?php echo number_format($remaining/100, 2, ',', '.'); ?> €</strong></p>
    </section>
<?php endif; ?>

<?php if ($isAdmin): ?>
<section>
    <h2>Admin: Spieler & Zugänge</h2>
    <div class="flex">
        <form method="post">
            <input type="hidden" name="action" value="create_user">
            <h3>Neuen Account anlegen</h3>
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

        <form method="post">
            <input type="hidden" name="action" value="update_password">
            <h3>Passwort ändern</h3>
            <label>Spieler
                <select name="user_id">
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
</section>

<section>
    <h2>Admin: Einzahlungen & Punkte</h2>
    <div class="flex">
        <form method="post">
            <input type="hidden" name="action" value="update_deposit">
            <h3>Einzahlung hinterlegen</h3>
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
            <button type="submit">Speichern</button>
        </form>

        <form method="post">
            <input type="hidden" name="action" value="add_score">
            <h3>Punkte eintragen</h3>
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

    <h3>Letzte Punktänderungen</h3>
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
                    <form method="post" style="display:flex; gap:.5rem; flex-wrap:wrap; align-items:center;">
                        <input type="hidden" name="score_id" value="<?php echo $score['id']; ?>">
                        <input type="hidden" name="action" value="update_score">
                        <input type="number" name="round_number" value="<?php echo $score['round_number']; ?>" min="1" style="width:80px;">
                        <input type="number" name="points" value="<?php echo $score['points']; ?>" style="width:80px;">
                        <button type="submit">Aktualisieren</button>
                    </form>
                    <form method="post" onsubmit="return confirm('Eintrag löschen?');">
                        <input type="hidden" name="score_id" value="<?php echo $score['id']; ?>">
                        <input type="hidden" name="action" value="delete_score">
                        <button type="submit">Löschen</button>
                    </form>
                </td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
</section>

<section>
    <h2>Admin: Phasenverwaltung</h2>
    <div class="flex">
    <?php foreach ($phases as $phase): ?>
        <form method="post" style="min-width:240px;">
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
    <?php endforeach; ?>
    </div>
</section>
<?php endif; ?>
</body>
</html>
