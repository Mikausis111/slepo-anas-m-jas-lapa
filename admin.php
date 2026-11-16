<?php
/* =============================================================================
   SLĒPOŠANAS NOMETNE — administrācija (admin.php)
   Jāatrodas tajā pašā mapē, kur index.php un config.php. Pirmajā atvēršanas reizē izveidojiet
   administratoru; pēc tam šī iespēja vairs nav pieejama.
   ============================================================================= */
declare(strict_types=1);
define('NOMETNE_CORE_ONLY', true);
require __DIR__ . '/index.php';

header('X-Robots-Tag: noindex, nofollow');
header('Cache-Control: no-store');

const IDLE_SECONDS = 1800;      // sesija beidzas pēc 30 min neaktivitātes
const MAX_ATTEMPTS = 5;         // pēc 5 neveiksmīgiem mēģinājumiem ...
const LOCK_MINUTES = 15;        // ... pieslēgšanās bloķēta uz 15 min
const STATUSES = ['jauns', 'rēķins nosūtīts', 'apmaksāts', 'atcelts'];

$pdo = db();

function a_url(string $s = '', array $q = []): string
{
    if ($s !== '') $q = ['s' => $s] + $q;
    return 'admin.php' . ($q ? '?' . http_build_query($q) : '');
}
function client_ip(): string { return (string)($_SERVER['REMOTE_ADDR'] ?? ''); }
function cents_from(string $eur): ?int
{
    $eur = str_replace([' ', '€'], '', trim($eur));
    $eur = str_replace(',', '.', $eur);
    if (!preg_match('/^\d{1,6}(\.\d{1,2})?$/', $eur)) return null;
    return (int)round((float)$eur * 100);
}
function valid_date(string $d): bool
{
    $dt = DateTime::createFromFormat('Y-m-d', $d);
    return $dt && $dt->format('Y-m-d') === $d;
}
function csv_cell(string $v): string
{
    if ($v !== '' && strpbrk($v[0], "=+-@\t\r") !== false) $v = "'" . $v;   // aizsardzība pret Excel formulām
    return '"' . str_replace('"', '""', $v) . '"';
}

/* ---------- pieslēgšanās stāvoklis ---------- */
$me = null;
if (!empty($_SESSION['admin_id'])) {
    if (time() - (int)($_SESSION['admin_seen'] ?? 0) > IDLE_SECONDS) {
        unset($_SESSION['admin_id'], $_SESSION['admin_seen']);
        flash('Sesija beidzās 30 minūšu neaktivitātes dēļ. Pieslēdzieties vēlreiz.');
    } else {
        $st = $pdo->prepare('SELECT * FROM mk_admins WHERE id = ?');
        $st->execute([$_SESSION['admin_id']]);
        $me = $st->fetch() ?: null;
        if ($me) $_SESSION['admin_seen'] = time(); else unset($_SESSION['admin_id']);
    }
}
$adminCount = (int)$pdo->query('SELECT COUNT(*) FROM mk_admins')->fetchColumn();
$section = (string)($_GET['s'] ?? 'pieteikumi');
$errors = [];

/* ============================== DARBĪBAS (POST) =========================== */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_check();
    $action = (string)($_POST['action'] ?? '');

    /* --- pirmais administrators --- */
    if ($action === 'setup' && $adminCount === 0) {
        $u = trim((string)($_POST['username'] ?? ''));
        $p1 = (string)($_POST['password'] ?? '');
        $p2 = (string)($_POST['password2'] ?? '');
        if (!preg_match('/^[\p{L}0-9._-]{3,40}$/u', $u)) $errors[] = 'Lietotājvārdam jābūt 3–40 rakstzīmēm (burti, cipari, . _ -).';
        if (mb_strlen($p1) < 12) $errors[] = 'Parolei jābūt vismaz 12 rakstzīmes garai.';
        if ($p1 !== $p2) $errors[] = 'Paroles nesakrīt.';
        if (!$errors) {
            $pdo->prepare('INSERT INTO mk_admins (username, password_hash, created_at) VALUES (?,?,?)')
                ->execute([$u, password_hash($p1, PASSWORD_DEFAULT), now()]);
            audit($u, 'Izveidots pirmais administrators');
            flash('Administrators izveidots. Tagad pieslēdzieties.');
            redirect(a_url());
        }
    }

    /* --- pieslēgšanās --- */
    if ($action === 'login') {
        $u = trim((string)($_POST['username'] ?? ''));
        $p = (string)($_POST['password'] ?? '');
        $since = date('Y-m-d H:i:s', time() - LOCK_MINUTES * 60);
        $st = $pdo->prepare('SELECT COUNT(*) FROM mk_login_attempts WHERE (ip = ? OR lower(username) = lower(?)) AND created_at > ?');
        $st->execute([client_ip(), $u, $since]);
        if ((int)$st->fetchColumn() >= MAX_ATTEMPTS) {
            $errors[] = 'Pārāk daudz neveiksmīgu mēģinājumu. Mēģiniet vēlreiz pēc ' . LOCK_MINUTES . ' minūtēm.';
        } else {
            $st = $pdo->prepare('SELECT * FROM mk_admins WHERE lower(username) = lower(?)');
            $st->execute([$u]);
            $row = $st->fetch();
            // salīdzinām arī neesošam lietotājam, lai atbildes laiks neatklātu, vai lietotājs eksistē
            $ok = password_verify($p, $row['password_hash'] ?? password_hash(random_bytes(8), PASSWORD_DEFAULT));
            if ($row && $ok) {
                $pdo->prepare('DELETE FROM mk_login_attempts WHERE ip = ? OR lower(username) = lower(?)')->execute([client_ip(), $u]);
                session_regenerate_id(true);
                $_SESSION['admin_id'] = (int)$row['id'];
                $_SESSION['admin_seen'] = time();
                if (password_needs_rehash($row['password_hash'], PASSWORD_DEFAULT)) {
                    $pdo->prepare('UPDATE mk_admins SET password_hash = ? WHERE id = ?')->execute([password_hash($p, PASSWORD_DEFAULT), $row['id']]);
                }
                $pdo->prepare('UPDATE mk_admins SET last_login = ? WHERE id = ?')->execute([now(), $row['id']]);
                audit($row['username'], 'Pieslēdzās');
                redirect(a_url());
            }
            $pdo->prepare('INSERT INTO mk_login_attempts (ip, username, created_at) VALUES (?,?,?)')->execute([mb_substr(client_ip(), 0, 45), mb_substr($u, 0, 100), now()]);
            $pdo->prepare('DELETE FROM mk_login_attempts WHERE created_at < ?')->execute([date('Y-m-d H:i:s', time() - 86400)]);
            $errors[] = 'Nepareizs lietotājvārds vai parole.';
        }
    }

    /* --- viss tālākais tikai pieslēgtam administratoram --- */
    if ($me) {
        $who = $me['username'];
        $back = (string)($_POST['back'] ?? a_url($section));
        if (!str_starts_with($back, 'admin.php')) $back = a_url();

        switch ($action) {
            case 'logout':
                audit($who, 'Atslēdzās');
                unset($_SESSION['admin_id'], $_SESSION['admin_seen']);
                session_regenerate_id(true);
                flash('Jūs esat atslēdzies.');
                redirect(a_url());

            /* pieteikumi */
            case 'reg_status':
                $id = (int)($_POST['id'] ?? 0);
                $status = (string)($_POST['status'] ?? '');
                if (in_array($status, STATUSES, true)) {
                    $st = $pdo->prepare('SELECT r.*, s.title, s.start_date, s.end_date, s.price_cents FROM mk_registrations r JOIN mk_camp_sessions s ON s.id = r.session_id WHERE r.id = ?'); $st->execute([$id]);
                    if ($r = $st->fetch()) {
                        $pdo->prepare('UPDATE mk_registrations SET status = ? WHERE id = ?')->execute([$status, $id]);
                        audit($who, "Pieteikums {$r['code']}: statuss “{$r['status']}” → “{$status}”");
                        $note = '';
                        if ($status === 'apmaksāts' && $r['status'] !== 'apmaksāts' && mail_enabled()) {   // tikai pārejot uz "apmaksāts", lai nesūtītu divreiz
                            $ok = mail_payment($r);
                            audit($who, "Pieteikums {$r['code']}: maksājuma apstiprinājuma e-pasts " . ($ok ? 'nosūtīts' : 'NAV nosūtīts (servera kļūda)'));
                            $note = $ok ? ' Maksājuma apstiprinājums nosūtīts uz e-pastu.' : ' E-pastu nosūtīt neizdevās — sazinieties ar klientu pats.';
                        }
                        flash("Pieteikuma {$r['code']} statuss: {$status}.$note");
                    }
                }
                redirect($back);

            case 'reg_delete':
                $id = (int)($_POST['id'] ?? 0);
                $st = $pdo->prepare('SELECT code FROM mk_registrations WHERE id = ?'); $st->execute([$id]);
                if ($code = $st->fetchColumn()) {
                    $pdo->beginTransaction();
                    $pdo->prepare('DELETE FROM mk_reviews WHERE registration_id = ?')->execute([$id]);
                    $pdo->prepare('DELETE FROM mk_registrations WHERE id = ?')->execute([$id]);
                    $pdo->commit();
                    audit($who, "Dzēsts pieteikums $code (un tā atsauksme, ja bija)");
                    flash("Pieteikums $code dzēsts.");
                }
                redirect($back);

            /* maiņas */
            case 'session_save':
                $id = (int)($_POST['id'] ?? 0);
                $f = [
                    'title' => trim((string)($_POST['title'] ?? '')),
                    'start_date' => (string)($_POST['start_date'] ?? ''),
                    'end_date' => (string)($_POST['end_date'] ?? ''),
                    'price' => (string)($_POST['price'] ?? ''),
                    'capacity' => (string)($_POST['capacity'] ?? ''),
                    'price16' => trim((string)($_POST['price16'] ?? '')),
                    'rental' => trim((string)($_POST['rental'] ?? '')),
                    'hotel' => trim((string)($_POST['hotel'] ?? '')),
                    'includes' => trim((string)($_POST['includes'] ?? '')),
                    'excludes' => trim((string)($_POST['excludes'] ?? '')),
                    'active' => !empty($_POST['active']) ? 1 : 0,
                ];
                $cents = cents_from($f['price']);
                $rentalC = $f['rental'] === '' ? 0 : cents_from($f['rental']);   // tukšs = šo pakalpojumu nepiedāvā
                $hotelC = $f['hotel'] === '' ? 0 : cents_from($f['hotel']);
                $p16C = $f['price16'] === '' ? 0 : cents_from($f['price16']);   // tukšs = visiem viena cena
                if ($p16C === null) $errors[] = 'Cenu no 16 gadiem norādiet eiro (piem., 144 vai 144,00) vai atstājiet tukšu.';
                if ($rentalC === null || $hotelC === null) $errors[] = 'Papildu pakalpojumu cenas norādiet eiro (piem., 60 vai 60,00) vai atstājiet tukšas.';
                if (mb_strlen($f['title']) < 3 || mb_strlen($f['title']) > 120) $errors[] = 'Nosaukumam jābūt 3–120 rakstzīmes garam.';
                if (!valid_date($f['start_date']) || !valid_date($f['end_date'])) $errors[] = 'Norādiet derīgus sākuma un beigu datumus.';
                elseif ($f['end_date'] < $f['start_date']) $errors[] = 'Beigu datums nevar būt pirms sākuma datuma.';
                if ($cents === null || $cents <= 0) $errors[] = 'Norādiet galīgo cenu ar PVN eiro, piem., 290 vai 290,00.';
                if (!ctype_digit($f['capacity']) || (int)$f['capacity'] < 1 || (int)$f['capacity'] > 500) $errors[] = 'Vietu skaitam jābūt no 1 līdz 500.';
                if ($f['excludes'] === '') $errors[] = 'Aizpildiet “Cenā nav iekļauts” (ja viss ir iekļauts, ierakstiet “Viss nepieciešamais ir iekļauts”). Tas novērš slēptas maksas.';
                if (!$errors) {
                    if ($id) {
                        $old = $pdo->prepare('SELECT * FROM mk_camp_sessions WHERE id = ?'); $old->execute([$id]); $old = $old->fetch();
                        if (!$old) redirect(a_url('mainas'));
                        $pdo->prepare('UPDATE mk_camp_sessions SET title=?, start_date=?, end_date=?, price_cents=?, price16_cents=?, rental_cents=?, hotel_cents=?, capacity=?, includes=?, excludes=?, active=? WHERE id=?')
                            ->execute([$f['title'], $f['start_date'], $f['end_date'], $cents, $p16C, $rentalC, $hotelC, (int)$f['capacity'], $f['includes'], $f['excludes'], $f['active'], $id]);
                        $note = (int)$old['price_cents'] !== $cents ? ' (cena ' . money((int)$old['price_cents']) . ' → ' . money($cents) . ')' : '';
                        if ((int)$old['price16_cents'] !== $p16C) $note .= ' (cena no 16 g. ' . money((int)$old['price16_cents']) . ' → ' . money($p16C) . ')';
                        if ((int)$old['rental_cents'] !== $rentalC) $note .= ' (noma ' . money((int)$old['rental_cents']) . ' → ' . money($rentalC) . ')';
                        if ((int)$old['hotel_cents'] !== $hotelC) $note .= ' (viesnīca ' . money((int)$old['hotel_cents']) . ' → ' . money($hotelC) . ')';
                        audit($who, "Labota maiņa “{$f['title']}”$note");
                        flash('Maiņa saglabāta.');
                    } else {
                        $pdo->prepare('INSERT INTO mk_camp_sessions (title, start_date, end_date, price_cents, price16_cents, rental_cents, hotel_cents, capacity, includes, excludes, active, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)')
                            ->execute([$f['title'], $f['start_date'], $f['end_date'], $cents, $p16C, $rentalC, $hotelC, (int)$f['capacity'], $f['includes'], $f['excludes'], $f['active'], now()]);
                        audit($who, "Pievienota maiņa “{$f['title']}”, " . money($cents));
                        flash('Maiņa pievienota.');
                    }
                    redirect(a_url('mainas'));
                }
                $section = 'mainas';
                $_GET['edit'] = (string)$id;
                $sessionForm = $f + ['id' => $id];
                break;

            case 'session_delete':
                $id = (int)($_POST['id'] ?? 0);
                $st = $pdo->prepare('SELECT title FROM mk_camp_sessions WHERE id = ?'); $st->execute([$id]);
                if ($title = $st->fetchColumn()) {
                    $n = $pdo->prepare('SELECT COUNT(*) FROM mk_registrations WHERE session_id = ?'); $n->execute([$id]);
                    if ((int)$n->fetchColumn() > 0) {
                        flash("Maiņai “{$title}” ir pieteikumi, tāpēc to nevar dzēst. Noņemiet atzīmi “Rādīt vietnē”, lai to paslēptu.");
                    } else {
                        $pdo->prepare('DELETE FROM mk_camp_sessions WHERE id = ?')->execute([$id]);
                        audit($who, "Dzēsta maiņa “{$title}”");
                        flash('Maiņa dzēsta.');
                    }
                }
                redirect(a_url('mainas'));

            /* atsauksmes */
            case 'review_publish':
            case 'review_reject':
            case 'review_delete':
                $id = (int)($_POST['id'] ?? 0);
                $reason = mb_substr(trim((string)($_POST['reason'] ?? '')), 0, 300);
                $st = $pdo->prepare('SELECT * FROM mk_reviews WHERE id = ?'); $st->execute([$id]);
                $r = $st->fetch();
                if (!$r) redirect($back);
                $label = "#{$r['id']} ({$r['author']}, {$r['rating']}★)";
                if ($action === 'review_publish') {
                    $pdo->prepare("UPDATE mk_reviews SET status='publicēta', reject_reason=NULL, moderated_by=?, moderated_at=? WHERE id=?")->execute([$who, now(), $id]);
                    audit($who, "Publicēta atsauksme $label");
                    flash('Atsauksme publicēta.');
                } elseif ($reason === '') {
                    flash('Norādiet iemeslu — bez iemesla atsauksmi nevar noraidīt vai dzēst.');
                } elseif ($action === 'review_reject') {
                    $pdo->prepare("UPDATE mk_reviews SET status='noraidīta', reject_reason=?, moderated_by=?, moderated_at=? WHERE id=?")->execute([$reason, $who, now(), $id]);
                    audit($who, "Noraidīta atsauksme $label. Iemesls: $reason");
                    flash('Atsauksme noraidīta.');
                } else {
                    $pdo->prepare('DELETE FROM mk_reviews WHERE id = ?')->execute([$id]);
                    audit($who, "Dzēsta atsauksme $label. Iemesls: $reason");
                    flash('Atsauksme dzēsta.');
                }
                redirect($back);

            /* datu pieprasījumi */
            /* kļūdu ziņojumi */
            case 'bug_fixed':
            case 'bug_reopen':
                $id = (int)($_POST['id'] ?? 0);
                $new = $action === 'bug_fixed' ? 'salabots' : 'jauns';
                $pdo->prepare('UPDATE mk_bug_reports SET status = ?, handled_by = ?, handled_at = ? WHERE id = ?')->execute([$new, $who, now(), $id]);
                audit($who, "Kļūdas ziņojums #$id: $new");
                flash($new === 'salabots' ? 'Ziņojums atzīmēts kā salabots.' : 'Ziņojums atvērts no jauna.');
                redirect(a_url('kludas'));

            case 'bug_delete':
                $id = (int)($_POST['id'] ?? 0);
                $pdo->prepare('DELETE FROM mk_bug_reports WHERE id = ?')->execute([$id]);
                audit($who, "Dzēsts kļūdas ziņojums #$id");
                flash('Ziņojums dzēsts.');
                redirect(a_url('kludas'));

            case 'request_done':
                $id = (int)($_POST['id'] ?? 0);
                $pdo->prepare("UPDATE mk_deletion_requests SET status='izpildīts', handled_by=?, handled_at=? WHERE id=?")->execute([$who, now(), $id]);
                audit($who, "Datu pieprasījums #$id atzīmēts kā izpildīts");
                flash('Pieprasījums atzīmēts kā izpildīts.');
                redirect(a_url('dati'));

            case 'request_delete_data':
                $id = (int)($_POST['id'] ?? 0);
                $st = $pdo->prepare('SELECT email FROM mk_deletion_requests WHERE id = ?'); $st->execute([$id]);
                if ($email = $st->fetchColumn()) {
                    $n = delete_personal_data($email);
                    $pdo->prepare("UPDATE mk_deletion_requests SET status='izpildīts', handled_by=?, handled_at=? WHERE id=?")->execute([$who, now(), $id]);
                    audit($who, "Datu pieprasījums #$id: dzēsti $n pieteikumi un to atsauksmes");
                    flash("Dzēsti $n pieteikumi un to atsauksmes. Pieprasījums atzīmēts kā izpildīts — atbildiet pieprasītājam e-pastā.");
                }
                redirect(a_url('dati'));

            /* administratori */
            case 'admin_add':
                $u = trim((string)($_POST['username'] ?? ''));
                $p1 = (string)($_POST['password'] ?? '');
                if (!preg_match('/^[\p{L}0-9._-]{3,40}$/u', $u)) $errors[] = 'Lietotājvārdam jābūt 3–40 rakstzīmēm (burti, cipari, . _ -).';
                if (mb_strlen($p1) < 12) $errors[] = 'Parolei jābūt vismaz 12 rakstzīmes garai.';
                $ex = $pdo->prepare('SELECT COUNT(*) FROM mk_admins WHERE lower(username) = lower(?)'); $ex->execute([$u]);
                if ((int)$ex->fetchColumn() > 0) $errors[] = 'Šāds lietotājvārds jau ir.';
                if (!$errors) {
                    $pdo->prepare('INSERT INTO mk_admins (username, password_hash, created_at) VALUES (?,?,?)')->execute([$u, password_hash($p1, PASSWORD_DEFAULT), now()]);
                    audit($who, "Pievienots administrators $u");
                    flash("Administrators $u pievienots.");
                    redirect(a_url('admini'));
                }
                $section = 'admini';
                break;

            case 'admin_password':
                $cur = (string)($_POST['current'] ?? '');
                $p1 = (string)($_POST['password'] ?? '');
                $p2 = (string)($_POST['password2'] ?? '');
                if (!password_verify($cur, $me['password_hash'])) $errors[] = 'Pašreizējā parole nav pareiza.';
                if (mb_strlen($p1) < 12) $errors[] = 'Jaunajai parolei jābūt vismaz 12 rakstzīmes garai.';
                if ($p1 !== $p2) $errors[] = 'Jaunās paroles nesakrīt.';
                if (!$errors) {
                    $pdo->prepare('UPDATE mk_admins SET password_hash = ? WHERE id = ?')->execute([password_hash($p1, PASSWORD_DEFAULT), $me['id']]);
                    audit($who, 'Nomainīja savu paroli');
                    flash('Parole nomainīta.');
                    redirect(a_url('admini'));
                }
                $section = 'admini';
                break;

            case 'admin_delete':
                $id = (int)($_POST['id'] ?? 0);
                if ($id === (int)$me['id']) { flash('Sevi dzēst nevar.'); redirect(a_url('admini')); }
                $st = $pdo->prepare('SELECT username FROM mk_admins WHERE id = ?'); $st->execute([$id]);
                if ($u = $st->fetchColumn()) {
                    $pdo->prepare('DELETE FROM mk_admins WHERE id = ?')->execute([$id]);
                    audit($who, "Dzēsts administrators $u");
                    flash("Administrators $u dzēsts.");
                }
                redirect(a_url('admini'));
        }
    }
}

/* ============================== CSV EKSPORTS ============================== */
if ($me && $section === 'pieteikumi' && isset($_GET['csv'])) {
    [$where, $params] = reg_filters();
    $st = $pdo->prepare("SELECT r.*, s.title, s.price_cents FROM mk_registrations r JOIN mk_camp_sessions s ON s.id = r.session_id $where ORDER BY s.start_date, r.created_at");
    $st->execute($params);
    $rows = $st->fetchAll();
    audit($me['username'], 'Eksportēts CSV: ' . count($rows) . ' pieteikumi');
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="pieteikumi-' . date('Y-m-d') . '.csv"');
    $out = fopen('php://output', 'w');
    fwrite($out, "\xEF\xBB\xBF");   // lai Excel pareizi rāda garumzīmes
    $head = ['Kods', 'Maiņa', 'Dalībnieks', 'Vecums', 'Līmenis', 'Vecāks', 'E-pasts', 'Tālrunis', 'Ēdināšanas norādes', 'Inventāra noma', 'Viesnīca', 'Summa EUR', 'Statuss', 'Pieteikts'];
    fwrite($out, implode(';', array_map('csv_cell', $head)) . "\r\n");
    foreach ($rows as $r) {
        $line = [$r['code'], $r['title'], $r['participant_name'], (string)$r['participant_age'], $r['ski_level'], $r['parent_name'], $r['email'], $r['phone'], (string)($r['food_notes'] ?? ''), $r['want_rental'] ? 'jā' : 'nē', $r['want_hotel'] ? 'jā' : 'nē', number_format((int)($r['total_cents'] ?? $r['price_cents']) / 100, 2, ',', ''), $r['status'], $r['created_at']];
        fwrite($out, implode(';', array_map('csv_cell', $line)) . "\r\n");
    }
    exit;
}

function reg_filters(): array
{
    $where = []; $params = [];
    if (!empty($_GET['sid'])) { $where[] = 'r.session_id = ?'; $params[] = (int)$_GET['sid']; }
    if (!empty($_GET['status']) && in_array($_GET['status'], STATUSES, true)) { $where[] = 'r.status = ?'; $params[] = $_GET['status']; }
    if (($q = trim((string)($_GET['q'] ?? ''))) !== '') {
        $where[] = '(r.email LIKE ? OR r.participant_name LIKE ? OR r.parent_name LIKE ? OR r.code LIKE ?)';
        $like = '%' . $q . '%'; array_push($params, $like, $like, $like, $like);
    }
    return [$where ? 'WHERE ' . implode(' AND ', $where) : '', $params];
}

/* ============================== IZKĀRTOJUMS =============================== */
function admin_start(string $title, ?array $me, string $section, array $counts = []): void
{
    $flash = flash();
    $tabs = ['pieteikumi' => 'Pieteikumi', 'mainas' => 'Maiņas un cenas', 'atsauksmes' => 'Atsauksmes', 'dati' => 'Datu pieprasījumi', 'kludas' => 'Kļūdu ziņojumi', 'admini' => 'Administratori', 'zurnals' => 'Darbību žurnāls'];
    ?><!doctype html>
<html lang="lv">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<meta name="color-scheme" content="light">
<title><?= e($title) ?> · Administrācija</title>
<style><?= site_css() ?>
body{background:var(--bg)}
.admin-top{background:var(--surface); border-bottom:1px solid var(--border)}
.admin-top .bar{max-width:1280px}
.admin-top form{margin:0}
.tabs{display:flex; gap:4px; flex-wrap:wrap; list-style:none; margin:0; padding:0}
.tabs a{display:inline-flex; align-items:center; gap:var(--s2); padding:var(--s2) var(--s3); border-radius:var(--r-1); color:var(--text-2); font-weight:600; font-size:var(--fs-sm); text-decoration:none}
.tabs a:hover{color:var(--text); background:rgba(11,11,14,.05)}
.tabs a[aria-current]{color:var(--text); background:var(--surface-2)}
.count{min-width:20px; padding:0 6px; border-radius:var(--r-pill); background:var(--accent); color:var(--accent-ink); font-size:var(--fs-xs); font-weight:700; line-height:20px; text-align:center; font-variant-numeric:tabular-nums}
.admin{max-width:1280px; padding-block:var(--s5) var(--s7); display:grid; gap:var(--s4); align-content:start}
.admin h1{font-size:var(--fs-2xl); margin:0}
.admin > .notice, .admin > .errors{margin:0}
.panel{background:var(--surface); border:1px solid var(--border); border-radius:var(--r-2); padding:var(--s5); min-width:0}
.panel h2{font-size:var(--fs-lg); margin-bottom:var(--s4)}
.panel + .panel{margin-top:var(--s4)}
.grid2 > .panel{margin-top:0}
.filters{display:flex; flex-wrap:wrap; gap:var(--s3); align-items:flex-end}
.filters label{min-height:2.6em; display:flex; flex-direction:column; justify-content:flex-end}
.filters > div{min-width:160px; flex:1 1 160px}
.filters .btn{flex:none}
.grid2{display:grid; grid-template-columns:repeat(auto-fit,minmax(min(100%,320px),1fr)); gap:var(--s4); align-items:start}
.tbl{overflow-x:auto; border:1px solid var(--border); border-radius:var(--r-2); background:var(--surface)}
.tbl table{margin:0; font-size:var(--fs-sm); min-width:900px}
.tbl td,.tbl th{padding:.55rem .6rem; white-space:nowrap}
.tbl td.wrap-cell{white-space:normal; min-width:260px; max-width:520px}
.tbl tr:last-child td{border-bottom:0}
.inline{display:flex; gap:var(--s2); align-items:center; margin:0}
.inline select,.inline input{min-height:36px; padding:var(--s1) var(--s2); font-size:var(--fs-sm); width:auto}
.inline select{padding-right:34px; background-position:right 8px center}
.btn-sm{--px:var(--s3); min-height:36px; font-size:var(--fs-sm)}
.btn-quiet{background:transparent}
.pill{display:inline-block; padding:1px var(--s2); border-radius:var(--r-pill); font-size:var(--fs-xs); font-weight:700; border:1px solid var(--border); color:var(--text-2)}
.pill.ok{color:#14653a; border-color:#b9dfc8; background:#e7f5ec}
.pill.warn{color:#7a5200; border-color:#ecd391; background:#fff3d6}
.pill.bad{color:#a3261d; border-color:var(--danger-bd); background:var(--danger-bg)}
.pill.new{color:var(--text); border-color:#c9cfda; background:var(--surface-2)}
.muted{color:var(--text-soft)}
.auth{width:100%; max-width:400px; margin:10vh auto 0; padding:var(--s6)}
.auth h1{font-size:var(--fs-2xl); margin:0}
.auth > * + *{margin-top:var(--s4)}
.auth .btn{width:100%}
.review-item{border-top:1px solid var(--border); padding:var(--s4) 0}
.review-item:first-of-type{border-top:0; padding-top:0}
.review-item:last-child{padding-bottom:0}
.review-item > * + *{margin-top:var(--s2)}
.review-actions{display:flex; flex-wrap:wrap; gap:var(--s2); align-items:center; margin-top:var(--s3)}
.review-actions input{flex:1 1 220px; width:auto}
textarea.short{min-height:90px}
</style>
</head>
<body>
<a class="skip" href="#saturs">Pāriet uz saturu</a>
<?php if ($me): ?>
<header class="admin-top">
  <div class="wrap bar">
    <a class="logo" href="<?= a_url() ?>"><span class="logo-dot" aria-hidden="true"></span>Administrācija</a>
    <nav aria-label="Administrācijas sadaļas"><ul class="tabs">
      <?php foreach ($tabs as $k => $label): ?>
        <li><a href="<?= a_url($k) ?>"<?= $section === $k ? ' aria-current="page"' : '' ?>><?= e($label) ?><?php if (!empty($counts[$k])): ?> <span class="count" aria-label="<?= (int)$counts[$k] ?> jauni"><?= (int)$counts[$k] ?></span><?php endif; ?></a></li>
      <?php endforeach; ?>
    </ul></nav>
    <form method="post" action="<?= a_url() ?>" class="inline">
      <?= csrf_field() ?><input type="hidden" name="action" value="logout">
      <span class="small"><?= e($me['username']) ?></span>
      <a class="btn btn-sm btn-quiet" href="index.php" target="_blank" rel="noopener">Skatīt vietni</a>
      <button class="btn btn-sm btn-quiet" type="submit">Iziet</button>
    </form>
  </div>
</header>
<?php endif; ?>
<main id="saturs" class="wrap admin">
<?php if ($flash): ?><p class="notice" role="status"><?= e($flash) ?></p><?php endif;
}

function admin_end(): void
{
    ?>
</main>
<script nonce="<?= csp_nonce() ?>"><?= site_js() ?></script>
</body>
</html>
<?php
}

function show_errors(array $errors): void
{
    if (!$errors) return; ?>
  <div class="errors" role="alert" tabindex="-1" id="kludas"><ul><?php foreach ($errors as $m): ?><li><?= e($m) ?></li><?php endforeach; ?></ul></div>
<?php }

function status_pill(string $s): string
{
    $cls = ['jauns' => 'new', 'rēķins nosūtīts' => 'warn', 'apmaksāts' => 'ok', 'atcelts' => 'bad',
            'gaida' => 'warn', 'publicēta' => 'ok', 'noraidīta' => 'bad', 'izpildīts' => 'ok'][$s] ?? '';
    return '<span class="pill ' . $cls . '">' . e($s) . '</span>';
}

/* ============================== PIESLĒGŠANĀS ============================== */
if (!$me) {
    admin_start($adminCount === 0 ? 'Pirmais administrators' : 'Pieslēgties', null, '');
    ?>
  <div class="panel-l auth">
    <?php if ($adminCount === 0): ?>
      <h1>Izveidot administratoru</h1>
      <p class="small">Šī forma ir pieejama tikai vienreiz — kamēr nav neviena administratora.</p>
      <?php show_errors($errors); ?>
      <form method="post" action="<?= a_url() ?>" class="stack">
        <?= csrf_field() ?><input type="hidden" name="action" value="setup">
        <div><label for="u">Lietotājvārds</label><input type="text" id="u" name="username" autocomplete="username" required maxlength="40"></div>
        <div><label for="p1">Parole <span class="hint">Vismaz 12 rakstzīmes</span></label><input type="password" id="p1" name="password" autocomplete="new-password" required minlength="12"></div>
        <div><label for="p2">Parole vēlreiz</label><input type="password" id="p2" name="password2" autocomplete="new-password" required minlength="12"></div>
        <button class="btn btn-primary btn-lg" type="submit" data-busy-text="Izveido…">Izveidot administratoru</button>
      </form>
    <?php else: ?>
      <h1>Pieslēgties administrācijai</h1>
      <?php show_errors($errors); ?>
      <form method="post" action="<?= a_url() ?>" class="stack">
        <?= csrf_field() ?><input type="hidden" name="action" value="login">
        <div><label for="u">Lietotājvārds</label><input type="text" id="u" name="username" autocomplete="username" autocapitalize="none" spellcheck="false" required autofocus></div>
        <div><label for="p">Parole</label><input type="password" id="p" name="password" autocomplete="current-password" required></div>
        <button class="btn btn-primary btn-lg" type="submit" data-busy-text="Pārbauda…">Ieiet</button>
      </form>
    <?php endif; ?>
  </div>
<?php
    admin_end();
    exit;
}

/* ============================== SADAĻAS =================================== */
$counts = [
    'atsauksmes' => (int)$pdo->query("SELECT COUNT(*) FROM mk_reviews WHERE status = 'gaida'")->fetchColumn(),
    'dati'       => (int)$pdo->query("SELECT COUNT(*) FROM mk_deletion_requests WHERE status = 'jauns'")->fetchColumn(),
    'pieteikumi' => (int)$pdo->query("SELECT COUNT(*) FROM mk_registrations WHERE status = 'jauns'")->fetchColumn(),
    'kludas'     => (int)$pdo->query("SELECT COUNT(*) FROM mk_bug_reports WHERE status = 'jauns'")->fetchColumn(),
];
$allSessions = $pdo->query('SELECT * FROM mk_camp_sessions ORDER BY start_date DESC')->fetchAll();
$here = 'admin.php' . (($_SERVER['QUERY_STRING'] ?? '') !== '' ? '?' . $_SERVER['QUERY_STRING'] : '');

switch ($section) {

/* ---------- Pieteikumi ---------- */
default:
case 'pieteikumi':
    $section = 'pieteikumi';
    [$where, $params] = reg_filters();
    $st = $pdo->prepare("SELECT r.*, s.title, s.start_date, s.price_cents FROM mk_registrations r JOIN mk_camp_sessions s ON s.id = r.session_id $where ORDER BY r.created_at DESC");
    $st->execute($params);
    $rows = $st->fetchAll();
    $overdue = date('Y-m-d H:i:s', strtotime('-7 days'));
    admin_start('Pieteikumi', $me, $section, $counts);
    ?>
  <h1>Pieteikumi</h1>
  <form method="get" action="admin.php" class="panel filters">
    <input type="hidden" name="s" value="pieteikumi">
    <div><label for="f-sid">Maiņa</label><select id="f-sid" name="sid"><option value="">Visas</option>
      <?php foreach ($allSessions as $s): ?><option value="<?= (int)$s['id'] ?>"<?= (int)($_GET['sid'] ?? 0) === (int)$s['id'] ? ' selected' : '' ?>><?= e($s['title']) ?></option><?php endforeach; ?></select></div>
    <div><label for="f-st">Statuss</label><select id="f-st" name="status"><option value="">Visi</option>
      <?php foreach (STATUSES as $s): ?><option<?= ($_GET['status'] ?? '') === $s ? ' selected' : '' ?>><?= e($s) ?></option><?php endforeach; ?></select></div>
    <div><label for="f-q">Meklēt <span class="hint">Vārds, e-pasts vai kods</span></label><input type="text" id="f-q" name="q" value="<?= e($_GET['q'] ?? '') ?>"></div>
    <button class="btn btn-primary" type="submit" data-busy-text="Atlasa…">Atlasīt</button>
    <a class="btn btn-quiet" href="<?= e(a_url('pieteikumi', array_filter(['sid' => $_GET['sid'] ?? '', 'status' => $_GET['status'] ?? '', 'q' => $_GET['q'] ?? '', 'csv' => 1]))) ?>">Lejupielādēt CSV</a>
  </form>
  <p class="small"><?= count($rows) ?> pieteikumi. Neapmaksātas rezervācijas, kas vecākas par 7 dienām, ir atzīmētas — tās var atcelt (sk. noteikumu 2. punktu).</p>
  <?php if (!$rows): ?>
    <div class="panel"><p class="muted" style="margin:0">Nav pieteikumu ar šiem nosacījumiem.</p></div>
  <?php else: ?>
  <div class="tbl"><table>
    <thead><tr><th>Kods</th><th>Maiņa</th><th>Dalībnieks</th><th>Vec.</th><th>Līmenis</th><th>Vecāks</th><th>E-pasts</th><th>Tālrunis</th><th>Ēdināšana</th><th>Papildus</th><th>Summa</th><th>Pieteikts</th><th>Statuss</th><th></th></tr></thead>
    <tbody>
    <?php foreach ($rows as $r):
      $late = in_array($r['status'], ['jauns', 'rēķins nosūtīts'], true) && $r['created_at'] < $overdue; ?>
      <tr>
        <td class="code"><?= e($r['code']) ?></td>
        <td><?= e($r['title']) ?></td>
        <td><?= e($r['participant_name']) ?></td>
        <td><?= (int)$r['participant_age'] ?></td>
        <td><?= e($r['ski_level']) ?></td>
        <td><?= e($r['parent_name']) ?></td>
        <td><a href="mailto:<?= e($r['email']) ?>"><?= e($r['email']) ?></a></td>
        <td><?= e($r['phone']) ?></td>
        <td class="wrap-cell" style="min-width:180px"><?= $r['food_notes'] !== null && $r['food_notes'] !== '' ? nl2br(e($r['food_notes'])) : '<span class="muted">—</span>' ?></td>
        <td><?= e(implode(', ', array_filter([$r['want_rental'] ? 'noma' : '', $r['want_hotel'] ? 'viesnīca' : ''])) ?: '—') ?></td>
        <td class="num"><?= e(money((int)($r['total_cents'] ?? $r['price_cents']))) ?></td>
        <td><?= e(date('d.m.Y H:i', strtotime($r['created_at']))) ?><?php if ($late): ?> <span class="pill warn">&gt; 7 d. neapmaksāts</span><?php endif; ?></td>
        <td>
          <form method="post" action="<?= a_url() ?>" class="inline">
            <?= csrf_field() ?><input type="hidden" name="action" value="reg_status"><input type="hidden" name="id" value="<?= (int)$r['id'] ?>"><input type="hidden" name="back" value="<?= e($here) ?>">
            <label class="hp" for="st-<?= (int)$r['id'] ?>">Statuss</label>
            <select id="st-<?= (int)$r['id'] ?>" name="status"><?php foreach (STATUSES as $s): ?><option<?= $r['status'] === $s ? ' selected' : '' ?>><?= e($s) ?></option><?php endforeach; ?></select>
            <button class="btn btn-sm" type="submit">Saglabāt</button>
          </form>
        </td>
        <td>
          <form method="post" action="<?= a_url() ?>" data-confirm="Dzēst pieteikumu <?= e($r['code']) ?>? To nevar atsaukt." class="inline">
            <?= csrf_field() ?><input type="hidden" name="action" value="reg_delete"><input type="hidden" name="id" value="<?= (int)$r['id'] ?>"><input type="hidden" name="back" value="<?= e($here) ?>">
            <button class="btn btn-sm btn-danger" type="submit">Dzēst</button>
          </form>
        </td>
      </tr>
    <?php endforeach; ?>
    </tbody>
  </table></div>
  <?php endif;
    break;

/* ---------- Maiņas ---------- */
case 'mainas':
    $editId = (int)($_GET['edit'] ?? 0);
    $form = $sessionForm ?? null;
    if (!$form && $editId) {
        foreach ($allSessions as $s) if ((int)$s['id'] === $editId) {
            $c2e = fn($c) => (int)$c > 0 ? number_format((int)$c / 100, 2, ',', '') : '';
            $form = $s + ['price' => $c2e($s['price_cents']), 'price16' => $c2e($s['price16_cents']), 'rental' => $c2e($s['rental_cents']), 'hotel' => $c2e($s['hotel_cents'])];
        }
    }
    $form ??= ['id' => 0, 'title' => '', 'start_date' => '', 'end_date' => '', 'price' => '', 'price16' => '', 'rental' => '', 'hotel' => '', 'capacity' => '', 'includes' => '', 'excludes' => '', 'active' => 1];
    admin_start('Maiņas un cenas', $me, $section, $counts);
    ?>
  <h1>Maiņas un cenas</h1>
  <div class="grid2">
    <div class="panel">
      <h2><?= $form['id'] ? 'Labot maiņu' : 'Pievienot maiņu' ?></h2>
      <?php show_errors($errors); ?>
      <form method="post" action="<?= a_url('mainas') ?>" class="stack">
        <?= csrf_field() ?><input type="hidden" name="action" value="session_save"><input type="hidden" name="id" value="<?= (int)$form['id'] ?>">
        <div><label for="m-title">Nosaukums</label><input type="text" id="m-title" name="title" value="<?= e($form['title']) ?>" required maxlength="120" placeholder="1. maiņa — Ziemassvētku brīvdienas"></div>
        <div class="grid2" style="gap:.8rem">
          <div><label for="m-start">Sākums</label><input type="date" id="m-start" name="start_date" value="<?= e($form['start_date']) ?>" required></div>
          <div><label for="m-end">Beigas</label><input type="date" id="m-end" name="end_date" value="<?= e($form['end_date']) ?>" required></div>
        </div>
        <div class="grid2" style="gap:.8rem">
          <div><label for="m-price">Pamatcena ar PVN, € <span class="hint">Katram dalībniekam (piem., pacēlājs + viesnīca, bērniem līdz 15 g.)</span></label><input type="text" id="m-price" name="price" inputmode="decimal" value="<?= e($form['price']) ?>" required placeholder="290,00"></div>
          <div><label for="m-cap">Vietu skaits</label><input type="number" id="m-cap" name="capacity" min="1" max="500" value="<?= e((string)$form['capacity']) ?>" required></div>
        </div>
        <div><label for="m-price16">Pamatcena no 16 gadiem, € <span class="hint">Ja pacēlāja biļete 16 gadus veciem ir dārgāka. Tukšs = visiem viena cena</span></label><input type="text" id="m-price16" name="price16" inputmode="decimal" value="<?= e($form['price16']) ?>" placeholder="369,00"></div>
        <div class="grid2" style="gap:.8rem">
          <div><label for="m-rental">Inventāra noma visai maiņai, € <span class="hint">Pēc izvēles pieteikumā. Tukšs = nepiedāvāt</span></label><input type="text" id="m-rental" name="rental" inputmode="decimal" value="<?= e($form['rental']) ?>" placeholder="60,00"></div>
          <div><label for="m-hotel">Viesnīca kā atsevišķa izvēle, € <span class="hint">Tukšs = nav izvēles (viesnīca jau pamatcenā)</span></label><input type="text" id="m-hotel" name="hotel" inputmode="decimal" value="<?= e($form['hotel']) ?>" placeholder="225,00"></div>
        </div>
        <div><label for="m-inc">Cenā iekļauts <span class="hint">Katrs punkts savā rindā</span></label><textarea id="m-inc" name="includes" class="short"><?= e($form['includes']) ?></textarea></div>
        <div><label for="m-exc">Cenā nav iekļauts <span class="hint">Obligāti. Piem., “Slēpju noma — pēc izvēles, maksā nomas punktā”</span></label><textarea id="m-exc" name="excludes" class="short" required><?= e($form['excludes']) ?></textarea></div>
        <label class="check"><input type="checkbox" name="active" value="1"<?= !empty($form['active']) ? ' checked' : '' ?>> <span>Rādīt vietnē un pieņemt pieteikumus</span></label>
        <p style="display:flex; gap:.5rem; flex-wrap:wrap; margin:0">
          <button class="btn btn-primary" type="submit" data-busy-text="Saglabā…"><?= $form['id'] ? 'Saglabāt izmaiņas' : 'Pievienot maiņu' ?></button>
          <?php if ($form['id']): ?><a class="btn btn-quiet" href="<?= a_url('mainas') ?>">Atcelt</a><?php endif; ?>
        </p>
      </form>
    </div>
    <div class="panel">
      <h2>Visas maiņas</h2>
      <?php if (!$allSessions): ?><p class="muted">Vēl nav nevienas maiņas. Pievienojiet pirmo — tā uzreiz parādīsies sākumlapā.</p><?php endif; ?>
      <?php foreach ($allSessions as $s): $taken = seats_taken((int)$s['id']); ?>
        <div class="review-item">
          <p style="margin:0"><strong><?= e($s['title']) ?></strong> <?= $s['active'] ? '<span class="pill ok">vietnē</span>' : '<span class="pill">paslēpta</span>' ?></p>
          <p class="small" style="margin:.2rem 0"><?= e(dmy($s['start_date'])) ?> – <?= e(dmy($s['end_date'])) ?> · <?= e(money((int)$s['price_cents'])) ?><?= (int)$s['price16_cents'] ? ' (no 16 g. ' . e(money((int)$s['price16_cents'])) . ')' : '' ?><?= (int)$s['rental_cents'] ? ' · noma +' . e(money((int)$s['rental_cents'])) : '' ?><?= (int)$s['hotel_cents'] ? ' · viesnīca +' . e(money((int)$s['hotel_cents'])) : '' ?> · aizņemtas <?= $taken ?> no <?= (int)$s['capacity'] ?></p>
          <div class="review-actions">
            <a class="btn btn-sm" href="<?= a_url('mainas', ['edit' => (int)$s['id']]) ?>">Labot</a>
            <a class="btn btn-sm btn-quiet" href="<?= a_url('pieteikumi', ['sid' => (int)$s['id']]) ?>">Pieteikumi</a>
            <form method="post" action="<?= a_url('mainas') ?>" data-confirm="Dzēst maiņu “<?= e($s['title']) ?>”?" class="inline">
              <?= csrf_field() ?><input type="hidden" name="action" value="session_delete"><input type="hidden" name="id" value="<?= (int)$s['id'] ?>">
              <button class="btn btn-sm btn-quiet" type="submit">Dzēst</button>
            </form>
          </div>
        </div>
      <?php endforeach; ?>
    </div>
  </div>
<?php
    break;

/* ---------- Atsauksmes ---------- */
case 'atsauksmes':
    $tab = in_array($_GET['t'] ?? '', ['gaida', 'publicēta', 'noraidīta'], true) ? $_GET['t'] : 'gaida';
    $st = $pdo->prepare("SELECT v.*, r.code, s.title FROM mk_reviews v LEFT JOIN mk_registrations r ON r.id = v.registration_id LEFT JOIN mk_camp_sessions s ON s.id = r.session_id WHERE v.status = ? ORDER BY v.created_at DESC");
    $st->execute([$tab]);
    $list = $st->fetchAll();
    admin_start('Atsauksmes', $me, $section, $counts);
    ?>
  <h1>Atsauksmes</h1>
  <p class="small">Atsauksmju tekstu labot nevar. Publicējiet arī kritiskas atsauksmes; noraidīt drīkst tikai aizskarošu saturu, personas datus vai reklāmu, un iemesls tiek ierakstīts žurnālā.</p>
  <ul class="tabs" style="margin-bottom:1rem">
    <?php foreach (['gaida' => 'Gaida pārbaudi', 'publicēta' => 'Publicētas', 'noraidīta' => 'Noraidītas'] as $k => $label): ?>
      <li><a href="<?= e(a_url('atsauksmes', ['t' => $k])) ?>"<?= $tab === $k ? ' aria-current="page"' : '' ?>><?= e($label) ?></a></li>
    <?php endforeach; ?>
  </ul>
  <div class="panel">
    <?php if (!$list): ?><p class="muted" style="margin:0">Šeit nav atsauksmju.</p><?php endif; ?>
    <?php foreach ($list as $v): ?>
      <div class="review-item">
        <p class="stars" style="margin:0" role="img" aria-label="Vērtējums: <?= (int)$v['rating'] ?> no 5"><?= str_repeat('★', (int)$v['rating']) . str_repeat('☆', 5 - (int)$v['rating']) ?></p>
        <p style="margin:.3rem 0"><?= nl2br(e($v['body'])) ?></p>
        <p class="small" style="margin:0">— <?= e($v['author']) ?> · <?= e(date('d.m.Y H:i', strtotime($v['created_at']))) ?>
          · <?= $v['code'] ? 'kods <span class="code">' . e($v['code']) . '</span>, ' . e($v['title']) : 'pieteikums jau dzēsts' ?>
          <?php if ($v['moderated_by']): ?> · <?= e($v['status']) ?>: <?= e($v['moderated_by']) ?>, <?= e(date('d.m.Y', strtotime($v['moderated_at']))) ?><?php endif; ?>
          <?php if ($v['reject_reason']): ?><br>Iemesls: <?= e($v['reject_reason']) ?><?php endif; ?></p>
        <div class="review-actions">
          <?php if ($tab !== 'publicēta'): ?>
          <form method="post" action="<?= a_url() ?>" class="inline">
            <?= csrf_field() ?><input type="hidden" name="action" value="review_publish"><input type="hidden" name="id" value="<?= (int)$v['id'] ?>"><input type="hidden" name="back" value="<?= e($here) ?>">
            <button class="btn btn-sm btn-primary" type="submit" data-busy-text="Publicē…">Publicēt</button>
          </form>
          <?php endif; ?>
          <form method="post" action="<?= a_url() ?>" class="inline" style="flex:1 1 360px">
            <?= csrf_field() ?><input type="hidden" name="id" value="<?= (int)$v['id'] ?>"><input type="hidden" name="back" value="<?= e($here) ?>">
            <label class="hp" for="rs-<?= (int)$v['id'] ?>">Iemesls</label>
            <input type="text" id="rs-<?= (int)$v['id'] ?>" name="reason" maxlength="300" placeholder="Iemesls (obligāts), piem., satur personas datus" required>
            <?php if ($tab !== 'noraidīta'): ?><button class="btn btn-sm btn-quiet" type="submit" name="action" value="review_reject">Noraidīt</button><?php endif; ?>
            <button class="btn btn-sm btn-quiet" type="submit" name="action" value="review_delete" title="Piem., pēc autora pieprasījuma">Dzēst</button>
          </form>
        </div>
      </div>
    <?php endforeach; ?>
  </div>
<?php
    break;

/* ---------- Datu pieprasījumi ---------- */
case 'dati':
    $list = $pdo->query("SELECT d.*, (SELECT COUNT(*) FROM mk_registrations r WHERE r.email = d.email) AS n
                         FROM mk_deletion_requests d ORDER BY d.status = 'jauns' DESC, d.created_at DESC")->fetchAll();
    admin_start('Datu pieprasījumi', $me, $section, $counts);
    ?>
  <h1>Datu pieprasījumi</h1>
  <p class="small">Atbildiet 30 dienu laikā. Pirms dzēšanas vai datu izsūtīšanas pārliecinieties, ka pieprasījums tiešām nāk no šī e-pasta īpašnieka (piem., atbildiet uz to e-pastā). Lai sagatavotu datu kopiju, atlasiet pieteikumus pēc e-pasta un lejupielādējiet CSV.</p>
  <?php if (!$list): ?><div class="panel"><p class="muted" style="margin:0">Pieprasījumu nav.</p></div><?php else: ?>
  <div class="tbl"><table>
    <thead><tr><th>Saņemts</th><th>Termiņš</th><th>E-pasts</th><th>Ziņa</th><th>Pieteikumi</th><th>Statuss</th><th>Darbības</th></tr></thead>
    <tbody>
    <?php foreach ($list as $d): $due = date('d.m.Y', strtotime($d['created_at'] . ' +30 days')); ?>
      <tr>
        <td><?= e(date('d.m.Y', strtotime($d['created_at']))) ?></td>
        <td><?= $d['status'] === 'jauns' ? e($due) : '—' ?></td>
        <td><a href="mailto:<?= e($d['email']) ?>"><?= e($d['email']) ?></a></td>
        <td class="wrap-cell"><?= nl2br(e($d['message'] ?: '—')) ?></td>
        <td><a href="<?= e(a_url('pieteikumi', ['q' => $d['email']])) ?>"><?= (int)$d['n'] ?></a></td>
        <td><?= status_pill($d['status']) ?><?php if ($d['handled_by']): ?><br><span class="small"><?= e($d['handled_by']) ?>, <?= e(date('d.m.Y', strtotime($d['handled_at']))) ?></span><?php endif; ?></td>
        <td>
          <?php if ($d['status'] === 'jauns'): ?>
          <div class="inline">
            <form method="post" action="<?= a_url() ?>" data-confirm="Dzēst VISUS e-pasta <?= e($d['email']) ?> pieteikumus (<?= (int)$d['n'] ?>) un to atsauksmes? To nevar atsaukt.">
              <?= csrf_field() ?><input type="hidden" name="action" value="request_delete_data"><input type="hidden" name="id" value="<?= (int)$d['id'] ?>">
              <button class="btn btn-sm btn-danger" type="submit">Dzēst datus</button>
            </form>
            <form method="post" action="<?= a_url() ?>">
              <?= csrf_field() ?><input type="hidden" name="action" value="request_done"><input type="hidden" name="id" value="<?= (int)$d['id'] ?>">
              <button class="btn btn-sm btn-quiet" type="submit">Atzīmēt kā izpildītu</button>
            </form>
          </div>
          <?php endif; ?>
        </td>
      </tr>
    <?php endforeach; ?>
    </tbody>
  </table></div>
  <?php endif;
    break;

/* ---------- Administratori ---------- */
case 'admini':
    $admins = $pdo->query('SELECT id, username, created_at, last_login FROM mk_admins ORDER BY username')->fetchAll();
    admin_start('Administratori', $me, $section, $counts);
    ?>
  <h1>Administratori</h1>
  <?php show_errors($errors); ?>
  <div class="grid2">
    <div class="panel">
      <h2>Visi administratori</h2>
      <?php foreach ($admins as $a): ?>
        <div class="review-item">
          <p style="margin:0"><strong><?= e($a['username']) ?></strong><?= (int)$a['id'] === (int)$me['id'] ? ' <span class="pill new">jūs</span>' : '' ?></p>
          <p class="small" style="margin:.2rem 0">Izveidots <?= e(dmy($a['created_at'])) ?> · pēdējo reizi <?= $a['last_login'] ? e(date('d.m.Y H:i', strtotime($a['last_login']))) : 'nav pieslēdzies' ?></p>
          <?php if ((int)$a['id'] !== (int)$me['id']): ?>
          <form method="post" action="<?= a_url() ?>" data-confirm="Dzēst administratoru <?= e($a['username']) ?>?">
            <?= csrf_field() ?><input type="hidden" name="action" value="admin_delete"><input type="hidden" name="id" value="<?= (int)$a['id'] ?>">
            <button class="btn btn-sm btn-quiet" type="submit">Dzēst</button>
          </form>
          <?php endif; ?>
        </div>
      <?php endforeach; ?>
    </div>
    <div>
      <div class="panel">
        <h2>Pievienot administratoru</h2>
        <form method="post" action="<?= a_url('admini') ?>" class="stack">
          <?= csrf_field() ?><input type="hidden" name="action" value="admin_add">
          <div><label for="n-u">Lietotājvārds</label><input type="text" id="n-u" name="username" autocomplete="off" required maxlength="40"></div>
          <div><label for="n-p">Parole <span class="hint">Vismaz 12 rakstzīmes. Nododiet to personīgi, nevis e-pastā.</span></label><input type="password" id="n-p" name="password" autocomplete="new-password" required minlength="12"></div>
          <p style="margin:0"><button class="btn btn-primary" type="submit" data-busy-text="Pievieno…">Pievienot administratoru</button></p>
        </form>
      </div>
      <div class="panel">
        <h2>Mainīt savu paroli</h2>
        <form method="post" action="<?= a_url('admini') ?>" class="stack">
          <?= csrf_field() ?><input type="hidden" name="action" value="admin_password">
          <div><label for="c-cur">Pašreizējā parole</label><input type="password" id="c-cur" name="current" autocomplete="current-password" required></div>
          <div><label for="c-p1">Jaunā parole</label><input type="password" id="c-p1" name="password" autocomplete="new-password" required minlength="12"></div>
          <div><label for="c-p2">Jaunā parole vēlreiz</label><input type="password" id="c-p2" name="password2" autocomplete="new-password" required minlength="12"></div>
          <p style="margin:0"><button class="btn btn-primary" type="submit" data-busy-text="Saglabā…">Mainīt paroli</button></p>
        </form>
      </div>
    </div>
  </div>
<?php
    break;

/* ---------- Žurnāls ---------- */
case 'kludas':
    $list = $pdo->query("SELECT * FROM mk_bug_reports ORDER BY status = 'jauns' DESC, created_at DESC LIMIT 500")->fetchAll();
    $pageNames = ['sakums' => 'Sākums', 'pieteikties' => 'Pieteikšanās', 'atsauksmes' => 'Atsauksmes', 'mani-dati' => 'Mani dati', 'kontakti' => 'Kontakti',
                  'privatums' => 'Privātuma politika', 'noteikumi' => 'Lietošanas noteikumi', 'atmaksa' => 'Atmaksas politika', 'sikdatnes' => 'Sīkdatņu politika', 'cits' => 'Cita vieta'];
    admin_start('Kļūdu ziņojumi', $me, $section, $counts);
    ?>
  <h1>Kļūdu ziņojumi</h1>
  <p class="small">Apmeklētāju ziņojumi no pogas “Ziņot par kļūdu”. Tie tiek automātiski dzēsti pēc 12 mēnešiem. Ja ziņotājs norādījis e-pastu, varat viņam atbildēt.</p>
  <?php if (!$list): ?><div class="panel"><p class="muted" style="margin:0">Ziņojumu nav.</p></div><?php else: ?>
  <div class="panel">
    <?php foreach ($list as $b): ?>
      <div class="review-item">
        <p style="margin:0"><?= status_pill($b['status'] === 'salabots' ? 'izpildīts' : 'jauns') ?> <strong><?= e($pageNames[$b['page']] ?? $b['page']) ?></strong>
          <span class="small"> · <?= e(date('d.m.Y H:i', strtotime($b['created_at']))) ?><?php if ($b['handled_by']): ?> · <?= e($b['status']) ?>: <?= e($b['handled_by']) ?><?php endif; ?></span></p>
        <p style="margin:0; white-space:pre-wrap"><?= e($b['message']) ?></p>
        <?php if ($b['email']): ?><p class="small" style="margin:0">Atbildei: <a href="mailto:<?= e($b['email']) ?>"><?= e($b['email']) ?></a></p><?php endif; ?>
        <div class="review-actions">
          <form method="post" action="<?= a_url() ?>" class="inline">
            <?= csrf_field() ?><input type="hidden" name="id" value="<?= (int)$b['id'] ?>">
            <?php if ($b['status'] === 'jauns'): ?>
              <button class="btn btn-sm btn-primary" type="submit" name="action" value="bug_fixed">Atzīmēt kā salabotu</button>
            <?php else: ?>
              <button class="btn btn-sm btn-quiet" type="submit" name="action" value="bug_reopen">Atvērt no jauna</button>
            <?php endif; ?>
          </form>
          <form method="post" action="<?= a_url() ?>" class="inline" data-confirm="Dzēst šo ziņojumu?">
            <?= csrf_field() ?><input type="hidden" name="id" value="<?= (int)$b['id'] ?>"><input type="hidden" name="action" value="bug_delete">
            <button class="btn btn-sm btn-quiet" type="submit">Dzēst</button>
          </form>
        </div>
      </div>
    <?php endforeach; ?>
  </div>
  <?php endif;
    break;

case 'zurnals':
    $log = $pdo->query('SELECT * FROM mk_audit_log ORDER BY id DESC LIMIT 300')->fetchAll();
    admin_start('Darbību žurnāls', $me, $section, $counts);
    ?>
  <h1>Darbību žurnāls</h1>
  <p class="small">Pēdējās 300 darbības. Žurnālu no administrācijas labot vai dzēst nevar.</p>
  <div class="tbl"><table>
    <thead><tr><th>Laiks</th><th>Kas</th><th>Darbība</th></tr></thead>
    <tbody>
    <?php foreach ($log as $l): ?>
      <tr><td class="num"><?= e(date('d.m.Y H:i', strtotime($l['created_at']))) ?></td><td><?= e($l['admin']) ?></td><td class="wrap-cell"><?= e($l['action']) ?></td></tr>
    <?php endforeach; ?>
    </tbody>
  </table></div>
<?php
    break;
}

admin_end();
