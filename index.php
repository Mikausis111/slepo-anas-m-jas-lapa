<?php
/* =============================================================================
   SLĒPOŠANAS NOMETNE — visa publiskā vietne (index.php)

   FAILI SERVERĪ (vienā mapē):  index.php · admin.php · config.php
   UZSTĀDĪŠANA:
   1. Hostinga panelī izveidojiet MySQL datubāzi un lietotāju (utf8mb4_unicode_ci).
   2. phpMyAdmin → jūsu datubāze → Import → schema.sql  (vai izlaidiet — tabulas
      tiks izveidotas automātiski pirmajā atvēršanas reizē).
   3. config.php ierakstiet datubāzes piekļuves datus un uzņēmuma rekvizītus.
   4. Ar FileZilla augšupielādējiet index.php, admin.php un config.php.
   5. Atveriet admin.php un izveidojiet pirmo administratoru.
   Prasības: PHP 8.1+ ar pdo_mysql, MySQL 5.7+ vai MariaDB 10.3+, HTTPS.
   ============================================================================= */
declare(strict_types=1);

if (!is_file(__DIR__ . '/config.php')) {
    http_response_code(500);
    exit('Trūkst faila config.php. Augšupielādējiet to tajā pašā mapē, kur index.php.');
}
require_once __DIR__ . '/config.php';

/* Virsrakstu fonts tiek pasniegts no šī paša faila (index.php?font=…), lai nekas netiktu lādēts no trešajām pusēm. */
if (isset($_GET['font']) && is_string($_GET['font'])) {
    $font = font_data()[$_GET['font']] ?? null;
    if ($font === null) { http_response_code(404); exit; }
    header('Content-Type: font/woff2');
    header('Cache-Control: public, max-age=31536000, immutable');
    header('X-Content-Type-Options: nosniff');
    echo base64_decode($font);
    exit;
}

date_default_timezone_set('Europe/Riga');
mb_internal_encoding('UTF-8');

function cfg(string $k) { return CONFIG[$k] ?? ''; }
function e($s): string { return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function money(int $c): string { return number_format($c / 100, 2, ',', ' ') . ' €'; }
function now(): string { return date('Y-m-d H:i:s'); }
function dmy(?string $d): string { return $d ? date('d.m.Y', strtotime($d)) : ''; }
function url(string $p = '', array $q = []): string
{
    if ($p !== '' && $p !== 'sakums') $q = ['p' => $p] + $q;
    return 'index.php' . ($q ? '?' . http_build_query($q) : '');
}
function redirect(string $to): never { header('Location: ' . $to, true, 303); exit; }
function is_https(): bool
{
    return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
}

/* ---------- drošības galvenes ---------- */
function csp_nonce(): string { static $n = null; return $n ??= base64_encode(random_bytes(16)); }
function send_security_headers(): void
{
    header("Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-" . csp_nonce() . "'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'; object-src 'none'");
    header('X-Frame-Options: DENY');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
    if (is_https()) header('Strict-Transport-Security: max-age=31536000');
}

/* ---------- sesija un CSRF ---------- */
session_name('nometne_sid');
session_set_cookie_params(['lifetime' => 0, 'path' => '/', 'secure' => is_https(), 'httponly' => true, 'samesite' => 'Lax']);
session_start();
send_security_headers();

function csrf_token(): string { return $_SESSION['csrf'] ??= bin2hex(random_bytes(32)); }
function csrf_field(): string { return '<input type="hidden" name="csrf" value="' . csrf_token() . '">'; }
function csrf_check(): void
{
    if (!hash_equals(csrf_token(), (string)($_POST['csrf'] ?? ''))) {
        http_response_code(400);
        exit('Formas derīgums beidzies. Atgriezieties, pārlādējiet lapu un mēģiniet vēlreiz.');
    }
}
function flash(?string $m = null): ?string
{
    if ($m !== null) { $_SESSION['flash'] = $m; return null; }
    $f = $_SESSION['flash'] ?? null; unset($_SESSION['flash']); return $f;
}

/* ---------- datubāze ---------- */
function db(): PDO
{
    static $pdo = null;
    if ($pdo) return $pdo;
    try {
        $pdo = new PDO('mysql:host=' . cfg('db_host') . ';dbname=' . cfg('db_name') . ';charset=utf8mb4', cfg('db_user'), cfg('db_pass'), [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);
    } catch (PDOException $e) {
        error_log('Nometne DB: ' . $e->getMessage());
        http_response_code(503);
        exit('Neizdevās pieslēgties datubāzei. Pārbaudiet db_host, db_name, db_user un db_pass failā config.php.');
    }
    $pdo->exec("SET time_zone = '" . date('P') . "', sql_mode = CONCAT(@@sql_mode, ',STRICT_TRANS_TABLES')");
    if (!$pdo->query("SHOW TABLES LIKE 'mk\\_meta'")->fetchColumn()) {   // pirmā palaišana: izveido tabulas
        foreach (array_filter(array_map('trim', explode(';', preg_replace('/^--.*$/m', '', schema_sql())))) as $sql) $pdo->exec($sql);
    }
    migrate($pdo);
    seed_example_sessions($pdo);
    retention_cleanup($pdo);
    return $pdo;
}

/* Pirmajā reizē, ja nav nevienas maiņas, pievieno trīs PARAUGA maiņas, lai vietne uzreiz rāda cenas un
   pieteikšanās pogas. Labojiet vai dzēsiet tās: admin.php → Maiņas un cenas. Izpildās tikai vienreiz. */
/* PARAUGA cenas (nomainiet uz īstajām: admin.php → Maiņas un cenas).
   Pamatcena = pacēlājs + viesnīca:
     pacēlājs darba dienās, 4 stundu biļete — līdz 15 gadiem 14 €/dienā, no 16 gadiem 24 €/dienā (Milzkalna cenrādis);
     viesnīca 45 €/naktī — APTUVENI.
   Inventāra noma 10 €/dienā (APTUVENI) ir vienīgais papildu pakalpojums pēc izvēles. */
function example_sessions(): array
{
    $exc = 'Inventāra noma — pēc izvēles, par papildu maksu (atzīmējiet pieteikumā)';
    return [   // title, start, end, price, capacity, includes, excludes, rental, hotel (0 = nav atsevišķa izvēle), price16
        ['Ziemassvētku brīvdienas', '2026-12-28', '2027-01-02', 30900, 24, "Pacēlāja biļete 4 stundām dienā — 6 dienas\nViesnīca — 5 naktis", $exc, 6000, 0, 36900],
        ['Februāra maiņa', '2027-02-15', '2027-02-19', 25000, 24, "Pacēlāja biļete 4 stundām dienā — 5 dienas\nViesnīca — 4 naktis", $exc, 5000, 0, 30000],
        ['Pavasara brīvdienas', '2027-03-15', '2027-03-19', 25000, 16, "Pacēlāja biļete 4 stundām dienā — 5 dienas\nViesnīca — 4 naktis", $exc, 5000, 0, 30000],
    ];
}

/* Datubāzes atjaunināšana esošām instalācijām, pa soļiem. Katrs solis izpildās vienreiz. */
function migrate(PDO $pdo): void
{
    $ver = (int)$pdo->query("SELECT v FROM mk_meta WHERE k = 'schema'")->fetchColumn();
    if ($ver >= 6) return;
    $add = function (string $table, string $col, string $def) use ($pdo) {
        if (!$pdo->query("SHOW COLUMNS FROM $table LIKE '$col'")->fetchColumn()) $pdo->exec("ALTER TABLE $table ADD COLUMN $col $def");
    };
    if ($ver < 2) {   // papildu pakalpojumi pēc izvēles
        $add('mk_camp_sessions', 'rental_cents', 'INT UNSIGNED NOT NULL DEFAULT 0');
        $add('mk_camp_sessions', 'hotel_cents', 'INT UNSIGNED NOT NULL DEFAULT 0');
        $add('mk_registrations', 'want_rental', 'TINYINT(1) NOT NULL DEFAULT 0');
        $add('mk_registrations', 'want_hotel', 'TINYINT(1) NOT NULL DEFAULT 0');
        $add('mk_registrations', 'total_cents', 'INT UNSIGNED NULL');
        // esošie pieteikumi patur cenu, par kādu tie tika iesniegti
        $pdo->exec('UPDATE mk_registrations r JOIN mk_camp_sessions s ON s.id = r.session_id SET r.total_cents = s.price_cents WHERE r.total_cents IS NULL');
    }
    if ($ver < 3) $add('mk_camp_sessions', 'price16_cents', 'INT UNSIGNED NOT NULL DEFAULT 0');   // cena pēc vecuma

    // Parauga maiņas, kuras administrators nav mainījis, pāriet uz pašreizējo cenu uzbūvi (pacēlājs + viesnīca pamatcenā).
    // Atpazīst pēc iepriekšējo versiju parauga cenām: [sākotnējā cena, tikai pacēlājs, viesnīca kā izvēle].
    $legacy = ['Ziemassvētku brīvdienas' => [29000, 8400, 22500], 'Februāra maiņa' => [25500, 7000, 18000], 'Pavasara brīvdienas' => [25500, 7000, 18000]];
    $st = $pdo->prepare('UPDATE mk_camp_sessions SET price_cents = ?, price16_cents = ?, includes = ?, excludes = ?, rental_cents = ?, hotel_cents = 0
                         WHERE title = ? AND ((price_cents = ? AND rental_cents = 0 AND hotel_cents = 0) OR (price_cents = ? AND hotel_cents = ?))');
    foreach (example_sessions() as $x) $st->execute([$x[3], $x[9], $x[5], $x[6], $x[7], $x[0], ...$legacy[$x[0]]]);
    // kļūdu ziņojumi
    $pdo->exec("CREATE TABLE IF NOT EXISTS mk_bug_reports (id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY, page VARCHAR(40) NOT NULL, message TEXT NOT NULL,
        email VARCHAR(254) NULL, status VARCHAR(20) NOT NULL DEFAULT 'jauns', handled_by VARCHAR(40) NULL, handled_at DATETIME NULL, created_at DATETIME NULL,
        KEY idx_bug_status (status)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
    // ēdināšanas norādes pieteikumā
    $add('mk_registrations', 'food_notes', 'VARCHAR(500) NULL');
    $add('mk_registrations', 'food_consent_at', 'DATETIME NULL');
    $pdo->exec("REPLACE INTO mk_meta (k, v) VALUES ('schema', '6')");
}

/* Maiņas papildu pakalpojumi un pieteikuma kopsumma. */
function session_days(array $s): int { return (int)round((strtotime($s['end_date']) - strtotime($s['start_date'])) / 86400) + 1; }
function plural_nights(int $n): string { return $n . ' ' . (($n % 10 === 1 && $n % 100 !== 11) ? 'nakts' : 'naktis'); }
function hotel_label(array $s): string { $n = session_days($s) - 1; return 'Viesnīca' . ($n > 0 ? ', ' . plural_nights($n) : ''); }
/* Atgriež rindas [nosaukums, centi]; pēdējā rinda vienmēr ir kopsumma. */
function price_lines(array $s, bool $rental, bool $hotel, int $age = 0): array
{
    $adult = $age >= 16 && (int)$s['price16_cents'] > 0;
    $lines = [[$adult ? 'Pamatcena (no 16 gadiem)' : 'Pamatcena', (int)$s[$adult ? 'price16_cents' : 'price_cents']]];
    if ($rental && (int)$s['rental_cents'] > 0) $lines[] = ['Inventāra noma', (int)$s['rental_cents']];
    if ($hotel && (int)$s['hotel_cents'] > 0) $lines[] = [hotel_label($s), (int)$s['hotel_cents']];
    $lines[] = ['Kopā', array_sum(array_column($lines, 1))];
    return $lines;
}

function seed_example_sessions(PDO $pdo): void
{
    if ($pdo->query("SELECT v FROM mk_meta WHERE k = 'seeded'")->fetchColumn()) return;
    if ((int)$pdo->query('SELECT COUNT(*) FROM mk_camp_sessions')->fetchColumn() === 0) {
        $st = $pdo->prepare('INSERT INTO mk_camp_sessions (title, start_date, end_date, price_cents, capacity, includes, excludes, rental_cents, hotel_cents, price16_cents, active, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,1,?)');
        foreach (example_sessions() as $r) $st->execute([...$r, now()]);
    }
    $pdo->exec("REPLACE INTO mk_meta (k, v) VALUES ('seeded', '1')");
}

/* Tās pašas tabulas, kas schema.sql failā (phpMyAdmin importam). */
function schema_sql(): string
{
    return <<<'SQL'
-- Slēpošanas nometne — datubāzes tabulas (MySQL 5.7+ / MariaDB 10.3+)
-- phpMyAdmin: izvēlieties savu datubāzi → cilne "Import" → izvēlieties šo failu → "Import".
-- (Ja to neizdarīsiet, index.php izveidos tabulas pats pirmajā atvēršanas reizē.)

CREATE TABLE IF NOT EXISTS mk_camp_sessions (
  id            INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  title         VARCHAR(120) NOT NULL,
  start_date    DATE NOT NULL,
  end_date      DATE NOT NULL,
  price_cents   INT UNSIGNED NOT NULL COMMENT 'Pamatcena ar PVN centos',
  price16_cents INT UNSIGNED NOT NULL DEFAULT 0 COMMENT 'Pamatcena no 16 gadiem centos; 0 = tāda pati kā price_cents',
  rental_cents  INT UNSIGNED NOT NULL DEFAULT 0 COMMENT 'Inventāra noma visai maiņai centos; 0 = nepiedāvā',
  hotel_cents   INT UNSIGNED NOT NULL DEFAULT 0 COMMENT 'Viesnīca visai maiņai centos; 0 = nepiedāvā',
  capacity      SMALLINT UNSIGNED NOT NULL,
  includes      TEXT NOT NULL COMMENT 'Cenā iekļauts, katrs punkts savā rindā',
  excludes      TEXT NOT NULL COMMENT 'Cenā nav iekļauts, katrs punkts savā rindā',
  active        TINYINT(1) NOT NULL DEFAULT 1,
  created_at    DATETIME NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS mk_registrations (
  id               INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  session_id       INT UNSIGNED NOT NULL,
  code             VARCHAR(16) NOT NULL,
  participant_name VARCHAR(100) NOT NULL,
  participant_age  TINYINT UNSIGNED NOT NULL,
  ski_level        VARCHAR(20) NOT NULL,
  parent_name      VARCHAR(100) NOT NULL,
  email            VARCHAR(254) NOT NULL,
  phone            VARCHAR(20) NOT NULL,
  status           VARCHAR(20) NOT NULL DEFAULT 'jauns',
  food_notes       VARCHAR(500) NULL COMMENT 'Ēdināšanas norādes; tikai ar nepārprotamu piekrišanu',
  food_consent_at  DATETIME NULL,
  want_rental      TINYINT(1) NOT NULL DEFAULT 0,
  want_hotel       TINYINT(1) NOT NULL DEFAULT 0,
  total_cents      INT UNSIGNED NULL COMMENT 'Kopsumma pieteikšanās brīdī centos',
  terms_version    VARCHAR(20) NULL,
  consent_at       DATETIME NULL,
  created_at       DATETIME NULL,
  UNIQUE KEY uq_reg_code (code),
  KEY idx_reg_email (email),
  KEY idx_reg_session (session_id),
  CONSTRAINT fk_mk_reg_session FOREIGN KEY (session_id) REFERENCES mk_camp_sessions (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS mk_reviews (
  id              INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  registration_id INT UNSIGNED NULL,
  author          VARCHAR(40) NOT NULL,
  rating          TINYINT UNSIGNED NOT NULL,
  body            TEXT NOT NULL,
  status          VARCHAR(20) NOT NULL DEFAULT 'gaida',
  reject_reason   VARCHAR(300) NULL,
  moderated_by    VARCHAR(40) NULL,
  moderated_at    DATETIME NULL,
  created_at      DATETIME NULL,
  KEY idx_rev_registration (registration_id),
  KEY idx_rev_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS mk_deletion_requests (
  id          INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  email       VARCHAR(254) NOT NULL,
  message     TEXT NULL,
  status      VARCHAR(20) NOT NULL DEFAULT 'jauns',
  handled_by  VARCHAR(40) NULL,
  handled_at  DATETIME NULL,
  created_at  DATETIME NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS mk_admins (
  id            INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  username      VARCHAR(40) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  created_at    DATETIME NULL,
  last_login    DATETIME NULL,
  UNIQUE KEY uq_admin_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS mk_login_attempts (
  id          INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  ip          VARCHAR(45) NOT NULL,
  username    VARCHAR(100) NOT NULL,
  created_at  DATETIME NOT NULL,
  KEY idx_login_time (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS mk_audit_log (
  id          INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  admin       VARCHAR(40) NOT NULL,
  action      TEXT NOT NULL,
  created_at  DATETIME NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS mk_meta (
  k  VARCHAR(40) NOT NULL PRIMARY KEY,
  v  VARCHAR(255) NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS mk_bug_reports (
  id          INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  page        VARCHAR(40) NOT NULL,
  message     TEXT NOT NULL,
  email       VARCHAR(254) NULL COMMENT 'Tikai, ja ziņotājs vēlas atbildi',
  status      VARCHAR(20) NOT NULL DEFAULT 'jauns',
  handled_by  VARCHAR(40) NULL,
  handled_at  DATETIME NULL,
  created_at  DATETIME NULL,
  KEY idx_bug_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
SQL;
}

function audit(string $who, string $action): void
{
    db()->prepare('INSERT INTO mk_audit_log (admin, action, created_at) VALUES (?,?,?)')->execute([$who, $action, now()]);
}

/* Automātiska dzēšana pēc glabāšanas termiņa — izpildās reizi dienā. Atsauksmes paliek (tās glabā līdz autora pieprasījumam). */
function retention_cleanup(PDO $pdo): void
{
    $today = date('Y-m-d');
    if ($pdo->query("SELECT v FROM mk_meta WHERE k = 'cleanup'")->fetchColumn() === $today) return;
    $cut = date('Y-m-d', strtotime('-' . (int)cfg('retention_months') . ' months'));
    $pdo->prepare('UPDATE mk_reviews SET registration_id = NULL WHERE registration_id IN
        (SELECT r.id FROM mk_registrations r JOIN mk_camp_sessions s ON s.id = r.session_id WHERE s.end_date < ?)')->execute([$cut]);
    $st = $pdo->prepare('DELETE FROM mk_registrations WHERE session_id IN (SELECT id FROM mk_camp_sessions WHERE end_date < ?)');
    $st->execute([$cut]);
    if ($st->rowCount() > 0) {
        $pdo->prepare('INSERT INTO mk_audit_log (admin, action, created_at) VALUES (?,?,?)')
            ->execute(['sistēma', 'Glabāšanas termiņa tīrīšana: dzēsti ' . $st->rowCount() . ' pieteikumi (maiņas beigušās pirms ' . $cut . ')', now()]);
    }
    $pdo->prepare('DELETE FROM mk_bug_reports WHERE created_at < ?')->execute([date('Y-m-d', strtotime('-12 months'))]);   // kļūdu ziņojumus glabā 12 mēnešus
    $pdo->prepare("REPLACE INTO mk_meta (k, v) VALUES ('cleanup', ?)")->execute([$today]);
}

function seats_taken(int $sid): int
{
    $st = db()->prepare("SELECT COUNT(*) FROM mk_registrations WHERE session_id = ? AND status != 'atcelts'");
    $st->execute([$sid]);
    return (int)$st->fetchColumn();
}

function delete_personal_data(string $email): int
{
    $pdo = db();
    $pdo->beginTransaction();
    $pdo->prepare('DELETE FROM mk_reviews WHERE registration_id IN (SELECT id FROM mk_registrations WHERE email = ?)')->execute([$email]);
    $st = $pdo->prepare('DELETE FROM mk_registrations WHERE email = ?');
    $st->execute([$email]);
    $pdo->commit();
    return $st->rowCount();
}

function lines(string $text): array
{
    return array_values(array_filter(array_map('trim', preg_split('/\R/', trim($text))), fn($l) => $l !== ''));
}
/* Vienota ikonu kopa: 24 px režģis, 2 px līnija, noapaļoti gali. */
function icon(string $name, string $extra = ''): string
{
    $paths = [
        'arrow'    => '<path d="M5 12h14M13 6l6 6-6 6"/>',
        'check'    => '<path d="M20 6 9 17l-5-5"/>',
        'mountain' => '<path d="m3 20 6.5-11 4.5 7.5L16.5 13 21 20z"/>',
        'copy'     => '<rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h8"/>',
    ];
    return '<svg class="icon ' . $extra . '" viewBox="0 0 24 24" aria-hidden="true" focusable="false">' . ($paths[$name] ?? '') . '</svg>';
}
function plural_days(int $n): string { return $n . ' ' . (($n % 10 === 1 && $n % 100 !== 11) ? 'diena' : 'dienas'); }

function field_error(array $errors, string $k): string
{
    return isset($errors[$k]) ? '<span class="error" id="err-' . e($k) . '">' . e($errors[$k]) . '</span>' : '';
}
function aria_err(array $errors, string $k): string
{
    return isset($errors[$k]) ? ' aria-invalid="true" aria-describedby="err-' . e($k) . '"' : '';
}

/* ---------- e-pasti (kopīgi ar admin.php) ----------
   Sūta ar servera mail() no adreses config.php → mail_from. Ja mail_from nav aizpildīts, e-pasti netiek sūtīti.
   Tikai darījuma e-pasti (apstiprinājums, maksājums) — nekādas reklāmas. */
function mail_enabled(): bool { return (bool)filter_var((string)cfg('mail_from'), FILTER_VALIDATE_EMAIL); }

function send_mail(string $to, string $subject, string $body): bool
{
    if (!mail_enabled() || !filter_var($to, FILTER_VALIDATE_EMAIL)) return false;
    $from = (string)cfg('mail_from');
    $clean = fn(string $v): string => trim(preg_replace('/[\r\n]+/', ' ', $v));   // nepieļauj galveņu injekciju
    $enc = fn(string $v): string => '=?UTF-8?B?' . base64_encode($clean($v)) . '?=';
    $name = (string)(cfg('mail_from_name') ?: 'Slēpošanas nometne');
    $reply = filter_var((string)cfg('email'), FILTER_VALIDATE_EMAIL) ? (string)cfg('email') : $from;
    $headers = implode("\r\n", [
        'From: ' . $enc($name) . ' <' . $from . '>',
        'Reply-To: ' . $reply,
        'MIME-Version: 1.0',
        'Content-Type: text/plain; charset=UTF-8',
        'Content-Transfer-Encoding: base64',
        'Auto-Submitted: auto-generated',
    ]);
    $body = chunk_split(base64_encode(str_replace(["\r\n", "\r"], "\n", $body)));
    try {
        return @mail($clean($to), $enc($subject), $body, $headers, '-f' . $from);
    } catch (Throwable $e) {
        error_log('Nometne mail: ' . $e->getMessage());
        return false;
    }
}

function mail_footer(): string
{
    $contact = array_filter([filter_var((string)cfg('email'), FILTER_VALIDATE_EMAIL) ? cfg('email') : cfg('mail_from'), cfg('phone')]);
    return "\n\nJautājumi: " . implode(', ', $contact)
         . "\n\n--\n" . cfg('company_name') . ', reģ. nr. ' . cfg('reg_number') . "\n" . cfg('legal_address')
         . "\nŠis ir automātisks paziņojums par jūsu pieteikumu.";
}
function site_link(string $p): string
{
    $base = rtrim((string)cfg('site_url'), '/');   // saites e-pastos tikai no config.php, nekad no pieprasījuma galvenēm
    return $base !== '' ? $base . '/' . url($p) : '';
}

/* Apstiprinājums pēc pieteikuma iesniegšanas. $r: pieteikuma rinda + maiņas title, start_date, end_date, price_cents. */
function mail_registration(array $r): bool
{
    $data = site_link('mani-dati'); $refund = site_link('atmaksa');
    $body = "Labdien, {$r['parent_name']}!\n\n"
          . "Esam saņēmuši pieteikumu nometnei.\n\n"
          . "Dalībnieks: {$r['participant_name']}\n"
          . "Maiņa: {$r['title']}\n"
          . 'Datumi: ' . dmy($r['start_date']) . ' – ' . dmy($r['end_date']) . "\n"
          . implode('', array_map(fn($l) => $l[0] . ': ' . money($l[1]) . "\n", $r['lines']))
          . "Cenas ir ar PVN; citu maksu nav.\n"
          . (!empty($r['food_notes']) ? "Ēdināšanas norādes: saņemtas (drošības nolūkos e-pastā tās neatkārtojam)\n" : '')
          . "Pieteikuma kods: {$r['code']}\n\n"
          . "Kas notiek tālāk\n"
          . "2 darba dienu laikā nosūtīsim rēķinu uz šo e-pastu. Vieta ir rezervēta 7 dienas līdz rēķina apmaksai.\n\n"
          . "Saglabājiet pieteikuma kodu — ar to varat atstāt atsauksmi vai dzēst savus datus"
          . ($data ? ": $data" : '.') . "\n"
          . ($refund ? "Atcelšanas un atmaksas nosacījumi: $refund\n" : '')
          . mail_footer();
    return send_mail($r['email'], "Pieteikums saņemts: {$r['title']} (kods {$r['code']})", $body);
}

/* Apstiprinājums, kad administrators atzīmē pieteikumu kā apmaksātu. */
function mail_payment(array $r): bool
{
    $body = "Labdien, {$r['parent_name']}!\n\n"
          . 'Esam saņēmuši maksājumu ' . money((int)($r['total_cents'] ?? $r['price_cents'])) . ". Vieta nometnē ir apstiprināta.\n\n"
          . "Dalībnieks: {$r['participant_name']}\n"
          . "Maiņa: {$r['title']}\n"
          . 'Datumi: ' . dmy($r['start_date']) . ' – ' . dmy($r['end_date']) . ", katru dienu 9:00–16:00\n"
          . 'Norises vieta: ' . cfg('camp_address') . "\n"
          . (!empty($r['want_rental']) || !empty($r['want_hotel']) ? 'Papildus: ' . implode(', ', array_filter([!empty($r['want_rental']) ? 'inventāra noma' : '', !empty($r['want_hotel']) ? 'viesnīca' : ''])) . "\n" : '')
          . "Pieteikuma kods: {$r['code']}\n\n"
          . "Pirmajā dienā lūdzam klātienē informēt instruktoru par dalībnieka veselības stāvokli, kas var ietekmēt slēpošanu (piem., alerģijas)."
          . mail_footer();
    return send_mail($r['email'], "Maksājums saņemts: {$r['title']} (kods {$r['code']})", $body);
}

/* Urbanist (variable) — Copyright 2020 The Urbanist Project Authors, SIL Open Font License 1.1 (woff2, base64). */
function font_data(): array
{
    return ['latin' => 'd09GMgABAAAAAGxoABQAAAAA1oQAAGv1AAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGoMfG98aHIFsP0hWQVKESAZgP1NUQVSBOCcuAIVOL34RCArybN8+C4NuADCBqEgBNgIkA4dYBCAFiWAHhkcMBxuMyRVsmxa92wGTe6v5QrMDLeiO4laKnFyZjahh4yCMZ7ZU+f+cA/9jDPvYHiBqlW13ooWQYzzISHpVacx11lUXLgTDlNuskytXKurSdfdFaT2hOAbtXd4IocK4gJa/RHzNzCwhdAoPPVhHe2NA5xyCxj4yWCJDxVzj96TrruqdR11PVO9uQjUarlEmFFM+zM6uNLdiqdAfe/3b12DB/rTlh4bltv6x0NecbzMMn6PN8UWA28SP1CGPROift/k658JbfbCtJCaUVyaqAoBUIbWpsCIkm7XD09z+vbvbdrtt5IoFkQNGCgpGkSoxqixQ0abPxsZsrA8/MGcCw/xi9mgDcOCUAYMeNzw/t/9jNRhI5IhURw56AVszNmJrVqyKGtuE0QJX6CkoKmU9JQQFA8XCCsz/7Hj/63vtfzz0f2/eKW/SfE9wi0Y02ASCFXBjYQ4GYf8BblaTgoeQABFICEQIBGuQUqUFamy70q6onXbPAz0T/b0X99MVs7a5T2fvzK4AT/IRBgGqvFTYdKex4uoXbSpktFm2CDYCfB7brM+6Zp0gpmOIDxBxZDCLECc8jjNpiqvVSvFypdp2q63OZKAe9mvzTmJXxzySKH3PWkNCKPz5oU2/HlUbc7nO7m1PezK9iVM6Ytr9I9a0X6saJWKE4CFYwOMF/qO1sFfVPYABJhUHKCNl/Z0JgosxBHeskZxYHoB71/t/UyBpgtPjPMJNWTTmjb0I70Du+G/O/5nVkKBS54rJRnrFHn3yJa57dpPgXjZIaYA0G6RYwEMwD1TctsD7CdGryQh6ySr8AhOUh6qW2zAfovuiPMai0OoWskJIRwcABPy9u+b+a2VZFFAYS0Qp1msId/+7pjl7abtNE2tADoxRVV3j3BTwmwVUBcxPSnD/bn4/Az6DJGeL1srmCu/xxIDImkDuWlpSdCuu3yXi/7/Osv3vXelYkpfeasHe3YBnQrusYAtYKidNk6JUvj1Ho/nWkWFYy2iHQQnX4aKck6Ii4Dpd2jZd+hbIvp9WUulCCGzhJQJChHcA2QRqW0//KZ62tBclrxximve/0s5oHHKEZs4sAW6EzAyYGbsdaGSff1PNb98dgNyBI8hNIznB+TnD66LZkEqXIbYuuofBQJzBAPIAIHcHALU7wJI+Q1DiPsYDkKu1AFlH2TFq1yGlR0CSR6TCkFzJoOTAdYrx51yUv/tV+4vuF51D9X/1eci/8cERtPWA4BaFXywJsC0J7OYJ5i2XfNmvKl7waKwLzVCIUZFK28x17Neu5qraXqQqG3koa1XZKqpSGIqyhC+CJ93diwASxK1cxnix8J3iRWz+f07fe+XqM1MzFklaSwxBmghbuLAFREIUcZSSpWacfr6dVRp5Hx8nPYbBj2ExYVhEMEEUU8QiiigiiMUPlfrhHpdFoJhZcbb1cY+GwATCAWJMMEioeJBEK0EetwJ5KpDve1CatQTRaH91CAJgNMAgEIzvpuU1IJD2dw/UhQbQJIBGANgHYBbA+Bx6ul9NehwcTvA7/HmocsuVA/+e+OvM2XPnzp26dPjGzkdFz7a82PwqEVj+gxfzxHBZdVl9RXlFdVV+XXJDfCv3bvZdxn36A+qDjAe0h5SH6T8THmMf456inmKeJ73oeFF80fmy41Xz68Kbwtv8O+19+r0m6OgNx686fvXxa05eduqSU5eeuuzMBWfPO3v+2QvOnXvuvAtnXDjz4umXR68MXx0a6x3rG+sf753oMqDn3Re7L/Wc6z03cHz4wPiuCcN1kTr5kL5L3xcvyxdN9fFOpCJSqZTHrqpK9WqyTCvJFRcOt+3NygcEgIANBALYAPI8901vaDJ+cEA/tqaDm24enwIOBoBGfgnvOeawtQ5sd/9miD6OGbvgGrRkbLqR7/dWDLgEARIR0DEBIYDAAYJFANhfARsMd/a4CFBbnCn9d2cnAqp5iYGYPQ0wwIWAa3cGzKpV8wG19THZ/7xfDgZA4EAv9SVAPwSbvMpZfTGyoz3WZW7p3GRtAgXIYtMG6+29PbW7duOs5+WsHTnjLltjahMZc/l0S7V487yoo0lejI0gsF9/1Kza5Kne6rFu65r+02muQ7IHU5uVizP/IYskSHJOrhwmtGLlDivaSyQTgW8SLDaJ+tFCfTcLa9rvg2oI0HoDgFs1gH4ADuNCrrheuaftbo35SkwQmB+0k5oCQ576dTQFEIsArvF5TUft3fysiyLN/kDpvKvrDWZvSOXeYsh0czVQfQHIvhnYxOFvrzXtCtwFZu60butyVP7leG/5sF6P1QIoAl8pD69s7dpsDB9M7v2kQOXZrV4DleRle7MbAwg3+TQxKlBso/Jk61npLnOiRgf5dNfDzLldVGguBjqKp1VeOZ7P/hskO0+YPWdm25lVvKRY3oy3dkzI+A3HEa8au5KtBpSRKq9cxifgyg9t44E7Ezrgw1yH+vL0f5XjlX1dB1w7arJmKKE3+69tx8H3O9yl91dH8qzbu+VaIHfcnLhYXEml9E1u0EMjNQBxJE7QteeIkW6ltCH79XNBAAVUXwGqAUNyHLiVik0/5hbVnoKxFjUfKSr0gi6x3bGyIiz4z0AbSX02Z22+zft5K//JI7kr16Qx5clMfMame1qmEQ3DBkMXrVEfL5M9/8e1+A9f37EoCjLkwQx8JIdP2Ac3MFTvzf7Rn7vKz/tZP+JbfY0x0ngRsSHRvXe/PgzRW7N9tGpTmdL+sWI7YBst2+TGtywjOtmQFmNys01yZ8Mj+NP8UaNe664u67SKtE5a8ZWuZPnIpTJJR1XXOuiC5GkjChMECIozQZnrQF7qmmSfFMPu+MYM65ht43DhSaZ1AAXVVyK17JnD3MSz5467Dck0/JQhJdOq+p2B5MOTAmYadxmLsJBLtSkX3IQ8GnQkXu8w07N4G4TegyDAypSEEYBLxm+FKLtcYnRpJ5u5FtkwOEu/wvIJb0gm+pXlPXOSD3aP6mXTAmys63oYiDveGsqz6o+69OGIpFq/lAyvOConcaP0/5O4hvOA4/+N1o2+WZrU16UbpEm6kvE2w/V+on4BCBPK3hNJgN2sz5/2xXdqvU/dcmxAPb8+0qa+NP9evWu5SFNHA8y9m+hSZu8w/9zfCRZZWEe226GISl2yVcdYd96u1wQiej3ijmY6frdcBiirtlThufPrO9vuGk3+IMY4+A57Fsr2uJTEbjvcztvumcb5xtje2Ewh9PTyBv0u7tSnEKxiq7jnYxVbxf70ksmu0s0WjL+dctUf16VJGn6qoMycDB4JCrIwKU3As4MlM2Z72HyHmGuFwEwOdnA0IIT2Hy3huKdsV/uA/XFi5GbV7fxnoXGTcS/tPF/AbG6NvSZ0E5iY60we5RhrtHPW5fEVDlzHEfobKTpbu9ZIQiem4bAvXDEq3NU+SN6Zo6yrHYk0ZT9CI+X8EPSUG3CPvRA3QJrllWzscHd0SuM4xFeIFVFpHlt2qCByp3zHYxzqt00pBf2u9mHKCfGyGaxqzZs02JaQUwrfUsphh6iNv0cGbTWd8O2u9KjkXPC0a5mwhHdT2bWrfehGT5lrRldpT4u+N8muH4DaNQ3Xm2xgMWHu78LWE2FZsu01rLS8IeJg8qPRyZ28HH6qtIuP8k3solVx95+b/1857i2g0GMgo4cyaI8cxetfIog1+Q/Zm28MsAigA7A61Bb/HNhxTCGl74DSVYZzbT2x2St+t/yVCDjI1DdAgEw6lUCgsxPuAi/OAKClHVapDYDF2z7a22XvpmYrsNo9/tCAZWaRu9Pcy91bpPpCfGHXxcr6WcB5p7l2fCxnQmxU2F0FJDJcofolPc7Vcmwzvcxz59TyFOg1FrlYCUxvSDQAbTd0rn520ncTr6I0pyMja+Uy0gqNtTPkA6vY4wycsbnl5QaZB+sdk71cGXiW6mBEpxnL1NPWIc2U+evb1VQHWLjopRUzbSPvtpYyuI3yVqN5+U/xQb+m6TixfS/+62QQwWpPbLjKksw7NpHoOynSZcgy+7BdHcTUVsTvwU3kRhNHQymS77ZGSgWkUa70XM1Ph3c0rrNWfY1Fz+A/6ipvsPDi9fie8Bh6m5BuVkK5pxkrXmE+ftWIYNL+mbYT8PHZvIMsU7lqNTKqNW43SFIRFDukryE8tvGhI2YHBKdlCRAYyVPLGjAA5E2ieIgl4lWZqIsLvn0Ox3oJ2BdFQX7ViUzXKT+AFqoyIRT+Yp5IpTEMyjwxuBPlQLBWr7DKaldf5SeZvKjONNKP6qgqvHXVyp5TrZH6yozOPVeRDiqcrNyNke4Uq8SfIPql5URKJ6J2qo3saCMymC30bCNLJjosU4C2MqaWO9vMNc0k0vnxBpVPICB5mtVm95hr9bUEz1glTmmHgj/B6WkZDXn7rgMdxoYdpN7hQDoVb40M7MGHJzDifDePkxutbfDOS7yNcoqVrusmlfai7VPDpWMEADz/6mTuNKdsrwP6pobFzQrPQAYtiReM4QvqpKVSUQOuSjQOM5ykMg7gqhDcqSbVEIfR4HxaGSnS7D1a1+Eu5+Sm5MzDmHo0AMoPhktwWT1fNDWFiuK7P/OiWQ9O4Mm6nh8nJ012LemWFfDF8VUnRHZCWP2QyptkjiHCExvIECsMGLlOgzLu2PQtd9ILp01WjQyVvB+mz6YsxNduAGbdktNf3CLqaoOkRlZXw2TTrkfBV/RgLf3IHPGFsHLwatWReSDqAsxyufb5XrOuN4Mcfce57bt8YVignzdN1MdoiVXoySVv9bREQZ/K3upEtT1tpN3KVyhaGG2u2vKLNI9asXvDL4ZlwkVPOOS85Pb+OVuClkcd2x180WZDCiQrwEnF1UBOK30Qaoe+fudXbJNpJKnUmXS5UcXInRDS9L9rFaV1tvAGUiv7gYKDnYZEMUIBfU33GecWBGWKkd8qlTVnPU4JN4nyJX3tE+RksMsjlUieBZJN37L1Zsh1Zv8/q5/QNnTZ9GINhUnP/H3zSNuBp4wcZoRiWzkuQ7AyIDaMDq86eWqvojWbG86UFhxgFrFSh7+WeLSNPWEvLk0GuLj1+dk2iuwuivlFYimYkyEwAMuJmyyVcYnRQ7e6+PILmFUGEy3OySWbS1+D6xoUxCcsZzTdWIuhfD25U6gcA+9w64EBo2hivVp51ZHrZ6oNgDvzEvVk0KvEdA0tc0+QSvDkGKMXM5rdFBdfwUqqxe7EpwFuvIAtzozOZ8UyjiO0OLMYSNUj1gKvz1E0w8cKDDi0alX8ryE/s99NnDSwAEjbnS9Rkh4TK4OhWVvjBKj/f6n0CK33FyU8i+ULhnK5e+l+CjVetrhTTeEJNqtWauNyMsmz229XBBOQYBd4+9/JCJ6Ks3qUAmuDpPUKrbQxuFqxU9Y4K+v89XLr3VKl0H0PbPXUSJGXsl2D7NDTsxOC6XmXWLkRfwwAITiIRAJ4CEMMfBAHCZxgA3vMgAdCMB1T4Y9YjMdkRFkBVwNhgkHQy0FYsEHhwAXhmSAKnwWISPjEApEEBaQsQaxejsuaDYgtZyguRiByQXETiLuw8Hg5Dp580PA1mhFjTNCKH39MxgbNjDMFwlSxFhCEBAqDEC52IgQh8uUgCtFwYsQyJs4ITvzbE0mUBJIsFYM0GRDmGRGbL5AFgpApDBYKm0ViYfHLmVhiBTpZspnKMUEnufIRFATNkVZCWC0y68VBobH3k36h086QusuU0DkSWyXi6N+gjQsu46kUiSojcSNYggMEYpJcPQQEhw4TwoAw0qXsIzKeMgKNe8wx4FLRYX8BgSUQEkUQK5ZFk91GCMkSZwgDl6LjvoMY7DPzYHpmJ/ABExvaHYRDMA0hnM+Mg4AZCMIjiLUkg+zCxv4CDgmMIIUQGMzhARZZ+CRoPE9rcousuCoUFxuNfN8ZwW4zgnObZHvKCVRYsVMp9lTGDmEPW3DBARZ0B+ELBPqnm8qHI3w6CB25RDly5ckHidiug4MQdEbHOXtK5xgqlYjwfvKAfqyNfUXfshkPOaTdA/c/Kj8RRoBX8mdytiLh7+O2SRXB8RyJGAFXPgSlzCb7YIIoOZ19UxvWO9B+bRQhEzh7pjestVcq7s914zXWKbQR9DXyGBq6oAB92UjNjLf4GQ5S6OW7Dn35dCDpZdfKio1rgJO+S0s6AknTm1btamC0YbHgZH8lEBQdYgN/1XMXKmtqAHdzEdtg6EeMsJRIz246VVZWZxPIzgZO5XcGyDq0JLtSjqqs+5yACwJUFVQmPkcqZDPydEpRnkwtABEcYSYrl0ZfcWnulvbTW+uh2i21ciLUAvIBgLQ0laq5pfaszdbUZLPZ7ThGo2Za0lLVel5eGzDEBTyoXwNsBpe84et39AbzxLVffl97WuQTZsT5ITULDKDJAB4B2BpgNOJjlu/L9ULzlLChcxsWpeGnNrmoJi+6IR2a1UuoNQs/gCH46/7rSt6OPZ17tPBk4d7anQ1VW67uuXTg7xOlp86dKTlz5tzZc6cunLlQfEnUtjawtR1s6QBtnQDqAQ29YJMXVA78K35gDACgAAB8sPGs5Xzh+eILhov6K4orqmuyW7xbuTOcu9n3su7T7md+OabykMokhfBYkZ6OrnucP1zNDkoslBhpnrpd0/ot61o6oWtPw908LvK/hxwbGGaoKCiU0zK1UhlXx7316i1/quW1I1y1Dxogh4cSwO1qOXsa70ysDRAYhhzrhYAj5nE0mnFStnnMJHH/Uzb/1ZJeD0BrS32fDOAWAPynJAFMhpLC68crEc9WQ844orYhAICvwxkRSPpS+3pyfkLFmm0J0ubj/ICBDIAtdvBUAsrJ95pocF/TsbCpQD0urpDEYktc3Ida5/3oZkeCGxwAkEobYYb2qT41kz/L3/1VAMDg6wOjxrzARUbXzDyRj2xeE+YGsKbM8Jxa5ZipjkeZjPZLAgzBg791qDLopRg7YY+t1uodohiKo6OVrRswsXAFVggJkhAV8kK70NsdEG3Fx8WDkplETUjVPwU4riyZtOe1hc+Oh88ZNBf8QvDic0Lbb/zbcw/cAgi1DsA/PpKOJIZfYf6ujtASmkMXQLAGMwRbIATfpscr/UV5nn5i6tl/2BYEAJsDHKwdAD2gf1ip6WYdQae3Dp/2Tufc95/XGj30gNJV/3rvlAuKld1AfDq1z74o8T8IAQsOxnDx8AlIbrhe3Yo1Wy7k3Ljz4HlV/n8+hp+xbjjvpnpX/DZOgEDBQoWLEEkhXqIkyVKkmWeBTAsttkSWbDlyFbjmuetqHfeXl9565Z0XHtF6jHRbnYue6OaZGtvt8EeDan/TU2SlO/baY59SdBAwcGgwYMLGnAlTZsSELIgYYcORHXsyDj5y4sOLt1H8uVpkkvEmmGKiyaYKEmaa6WaIEy1GrBCp5phplnSzfTLXCksts1ye+fI5y6DSg0qVWypUKlelEgTQhgDhYkKctw4y9PmW+6VMboMGQNfyawgFgJfmDRfmas76EaJlVTRSdH1e9miUGABMVTRauJ6qaIyYeqqisSL0lKtx+2BDGQa0WNBvkH/xW2DozYBRVwDEwQB7CwAYSLMyTQUKVDbiIV0CDZwyuD10nVfNma4mvVdwmgIOArVjseb0Ul8CKwxApSzHyDpVQgHocvHKgSgPSDNopQYWK1Q2gJ5/hKQR5prCdQZuVBSan902XISI6AQnfhA6cNQkuANM2yEc09VchGwQMxukcwju8KCLbTUcYxmzhKMJ1LslqDhsJsFr54PNbYf74zeL26zDYjrBmNlsTDbKSwQdTJe2g9emCJLwZPOub+BGEU4Ih3usNotQ1KbN2yTtFzovdCG5dMn0oO0L1Hr8yLIcHJk/xVgSHH9kKmXHo4hOxya3nXAjNjbxKywy7A7lZpoMYhhmP55ojTSaLSo2xmCQIykM7Ij145hMyaB08GobHLZ4lNd8e2zJdM86mJrEcEPLSUZVOuI3bxIrhshKIbGjLI99agXxBACFlK0/xjiyzC1brbUxVsqM8KYSzFoH2qUeJz1xMIQnOSqc1UofRgE6fjnA5TTLsBBIdQUEdAW7hFypHTgjHnekkDgDpP5NzwqZvzmPMJ2qijpu4lDMOynP9c16cV7fp4wYPnvnKyU0EBZV/hQf7wtBCtQqfWZUT+peMjy7XfBgDiCGItpsw7juEeMJ9pSmHqRaChpWvFwxZX7bSe+xuBpW/wo9TKJ2Col1+BjY04dtYqY9zMhxrcPyR2CrfiHLzjRq01AaRRJ58JnlSst77Un6NGholmcfGs/VxDWDfUGfMVYiI17Y1JxZmpq4RkAUUBjhF5hxE2wHxijIohH2uTo+URuqBYSnBtwfcq9Pg56hvEOuFDCajnapu7g+j2QjKqBztCeWJo9K9O214pmxgkWifv+11on5i0nHWeN3TLF+r/DvedSy6XOmmkkJjbSNzBmC17zSQls9JuJuzFUqKNATPGssFPtjQlWyZmXNnfbuOMnFYvS8iPK29OoWlmsJTc9lwGC6p0c+IduGurJPXHAXCsGBZK5FVfSMafBaOuReDDMkLmCWLEOaIuQgvDaWAnYGQ965pWGf4c5E10HdyQuah6ibpcQwiEEnCD/eDrsAG+6abjWc762hs3nLbHVesT819caeUR6R4ZPv6TRsd6r6a+pBnefqDM2ZUYxdTj7MdUeF42Vj4g1GM5tz/5JmfbltZzoUncZ6ctz4TzZ5GvZxTCdH9rOkGDnJCtw3IOANpaGa+GeQl3mJc5cdsUqXmxCcLaLQpRM07Pr7qpKLincKKncuhTnFA4+n0MFTCXb/N+KOcx7hfo8DSfa6hDGO1/zY+R1D0twwDoLjp7RjCR0qSArh32E9IpTkbYwSoo9/ushO0LDHQNbJzbUDbO4braeQZNKenuVu4EPeWeyqeOZ9semoq6bBseh9FBrYw3bIc/bh1Lp8h6E9yvMYP6426sqxTid/pjOGGCPM2WIg2GJ7s2WZ9Tw4dsogsqb38DybRDY7wmYbzEIbJMtve7+NcEmzY36Licy0fZaF8M3QtmIxpP0t+rUFtr7D+J3//9acChILil8dRhhDjwzXsv1Efd2tj698lzlnhty3hh/NffYyEJnjiHa/+5JHfjXW/He/eRv5RSIGcWE0dAq4lP4xGHHxqdLVobtOIofzNkwiJFQICpVWbWT4pIuRU4YyFtxFeXQyae7iLM5wbz3N1GQ2R9z4We16l866gZGO5mZQqN5eXOB/vNudxYDKWyHB581Vy/wnqOFiElcr4xW/m7fi74FSf8sxqDyTqoc/Oj/7HnmJwgxSlWsmXn3+e+CD/ynUPzlCvZQp//hVqeIv78ERomYbIhMDBcP0kDBuzDqvHGarMsiTebizxwSXnabNhzApIBepxpes5psT5f1XDaF0PMEw4eiznL6/UvP/1O918Pzct1wsNIhClNPpUcQvuCnKueVviMB9ULzOjnweMm4eRf6R5XmmH5efYWyWuYzk8XNxyEZetB5sWyc7zNHJZmvryHSMk9yge/LErRRPZpk9oH77u1WSIkCe3KPuqDV9zDFF9UMIU47ZnNN0SSlK/I7IMOMEKe+BBHKlv1N6JEzJvzXMTYl/QQ5+M/WHVMt6kQfoJnifSoBwnhXyg2k/s6btryRkZHh3TmFOXBlDBASfzjmjLlfW3JD66bZi0MPvEKxLYYTMplumGGGs5Yxp6DYP2/Y6Z/PCZs517NKqKnVRyZ1ClGRzELGmGb3bbpGMDSU5orPQPDMNdM9toG4qpjicNa0jkzfFcjHnVsPArtAz/HQ77QS7bdZ5lZYzNlybbFctigUc+DuqKkTpHSp14bNXybNCf/mlURiovjYKfcXnxnDvzie57h/sQW5e6q1iHPckvXQ3LGdedl/ZVfcjGNguTpx1pDIvkUm07OkoQfmLBLfamEF6aXCKnCQnzD48bL/+4eakQ5Ghna6MEX+Gi/ciGJ2XAveMunZd9stiZGcdvuWRb29Jscklc4TYMCr9G2hmezN1XMwE+DGR/d2RQa/XIx3q0IFG0BE1nuz4bTUY9tr+4eiFEj98CT36kAhdDLu7KXTneG9UESABjXwo3U0X7TAg1+UTMn56ykqPU7oWxhVJR34SKeqtNkIRCVuZScRWFGUQbBaUGDIqCyC9GAWoQOOf+hPTygV2u3LBiek/9Y37Pbp5FRY0QfSiYGP+NLejJ3OmuCRrxt4zzTZUPCnC51rQvAqP7b8vuNHyQ31qSv1Py37LIhPiFnQDpuByTmdnzuWCAhJ3dV7KKcAAzd4qqCq1cuo/6ilmzX/A0oouM7Zuy75kLGRe6dp6KduImWBBrHu0yIIuTlAgivvFhy5+xkZCeyZwEG4vgDu4Nv+lP35RMd/eqVlw6twfGqjHs0NcZ8VQ5c90xYZp9pae7BlzSfaMfdcFtpG/F9lQKOhewzWXecxu1vw4cf+7GkyMNkFgHgntfbq3uir1KbCrpPcEsHFJtYVRmKq/aF4bsAZiqintB2RQK8ZH9GDo8POCosY3t06bwI6Ph7QDE/D+VAkBk8OvJqlz1XxnyXypY1bTtPS7h8B3ZgHHkvivK1vXR1ksLOwt61NnYuDp7dr4p37ygmq+3c4sMpFtbCJDGVQeviF/mmvvyZopNmXfse+a5hgrsf9SNct+wb4dJWmUGoto67phVqNp7f5oGMGWT6q2CjvWHWJ5uCZqWwDGJ+yKLL7tavRI+u/yOuOHQ3fPOvoP/PRD3Nksn76LbmXubYsWwj89JPgAIPgggD7BowV72/e7V8ixioPvKf2oWjmRX6A+OqbSRKXdCiaa8Xgrlcos9hKDNXqRb9TPpYmQ79CZcU1mTznv3s2gPGFYMVOdd42avU1/YHj0VZnvCbx9e04EcwZR6MTrfxWJL1+JJyaNCwVKGgTs7s263bkFPxPFjyTL3NOsYTtmU3szUkHQLQynHywMmO2iv5m2rdyLVQHnFTC3b6ALBlLyjOlURd7uePaKRucXsyu3l5c0jLwSVmtuYHaUw3hVG/jv8NvWZ/JBqdD6oLD5gr4N0pXVTq+XNewqMjUcMtcGmHbYBD37BH16CgF7wt5vfRtX74NDcBvv7mhZedUhG+du2fK9UkZ8BO25yAOuXudH2t3O/d7t1e/bve6OgMOxeabmlVW1KwtqrSc1zU5ppt2OUZHTexcUwc/ujV/qQ/WjDv45Tp26vA+3Bwcm+JsG7v8wQ+Z7PwYKJEABJawWjEBq4IL4l4eh4f8sc4/C+UMFZu0peksL7ZRWnTHZ2HQiQ73xaFFMruykqlNOH1FpM4c7ZUrloFw6otYohgdlIMyZsYmYXplFxVdX0zhVgJne3sgUkVK9SIXxWldE9YP6hPwgUqlxZwpLf5RRvSP19jwzdTFfaN+SwxXvksHZm70Tqv6794hgP76iPCArgL6pfJAgKjUMFq1jeS4jVKZzxUQMWy67ND2fK+rq4vJ4XWxhFwiomtv6ZfPmL60a2snm5pM0jXW0MJJ/HALz6qGDkfzRwgWjHaqDctmISiusK1d2KeiiXU3mcJcM+Hj/bcVg+DcN5voXm2u+tGgpJzc1H6bJzJsTwuRa0ZGoFiw5r0/JH1IoBEN9cjG9iQTG/vqoh3mOR+aOFVg1k7TmZtqkhgtMymMFjyyewkoFCfDJI57rQSaNHySQHF8fqH9VW/uyXk45Ul93mCLP3ZUZiXUSsU/WdB5ia6Edi7rOrdAIweNdZb8+39HWIO0X5/YLJYK+flGetE8seOqiN9Y+CeDhIsMvQ3eMUdOdOjPPnLGEL+iw53BAho4LA4QLOsQ2qfOTdXXB53lhUBgX4tZBdfMI2KJiLCFaFCwXi77Nc43E44B/5LuHlgnoe6DSUZxQfprf2O2Ra4tfSZSbGrGkNFuElJFQgH4cyRvOL1RM0Bqa0yc1mvSTsd0JmqJw2BjJZ56R21W0EbmKPrxFKZXulgtH1GrxsBGBibNVKohKp1ZXv9m0GiqYi2t3jtIo0j6WxHBUozkKFmxyyhMA1G/QjEIUxojLgrLU8pExBdjiWPvid1++31iz/IzLOL0VmIRKtoDpVFQfTdrDkhiOa6M4Y/Go1sDU26CCyBmU2gp6RkYFmVLDIC91xlOvzGxqJd09+gwyb0/wDqqvNcZcPR/52qqhTJKx1g3SXiV/SKbIHe5V5JGOQaEWDvZJwagYWQKczsDJ721kwMXKnO81pu8nb8jMwcnu2br6B1mOkLu+Dk2YW1hBoy7tGtZPCia2bZuJGzTm0qph7Jcx0zp6ufmNy92NLS/1zwzItJXuwfJ1xxjV3am351moXmAd4RdZ2Qmg+9NP2fku8Tm/nHVyej5noA10gjndfq9GFAOzqSZw8ammQfdXp2hK0SXPHNKo6CNdCqV8UKYY1qpkwwcVoOAbqJZApC6e8KBIQLetil01mObW8mXz5q+tMCdDbDPRTdmVgwrpsCS/nqpzZKhTDkgDTornx9ZvD7Lq70xwMZI2axsiPxcyRf6Wg9QFIJIUgWhiJAKXrPFrVrj3pLHVORxp1W58rvmiIoyhRztTEkQ+3r9oAtAkBAIVq4dhndjuOwlCDYhhq6p/wgLyKDe1x2zelcaT7c4THVAl+hfg+eRJJiaB566OU0j3HRAriK5WNqEoDVuAw2GNRWkE1ixTD2qWBoM0YnHIfE0amlZNTa+mz4DAfO5XsIoL8WIPQ4dBHATivgK1VAFR6NTqGiqNXqWMQdGmvnsINLxG2uugtZxDTjPHOlatwk1eHcCtefW3d9sd5wQ4vIy2t2rDqN/42O/oux4Ma35Vfz/It66xHlB911iw7kTL1pYB78x37bDoR08f/uaU867TERMI2sXcphvNUA6UflBA5BCYdwxaLaL3bhYwGXWC9F7RaugdtBfB7pfl8bdw4fgEMMul9Ly+4QJ+vt2OX9AwTVbpRrbqphGT4fl1F/4fwtpQdaiHtbh7N3fhoa5y6RaeuC/89o07OItHd4E3n+yBDX+BggQKK410dmxqaucJwV4UlVxhS6dSK9IpFVTIVHD6tLGwcCrfeLoYR9xbNrZz/OAgjWyDwAcX22m9ejIfImNLy4lschWRXkrOzS3dk6wu6BgrtWDwmgI0BmNGkzUYiIqqNyhaEjIUYzLdQaVMMcDyobgo5NF11PziyXN6cDGd2+hbKRwWt0FtdSinw7NmnwAOLrablpKbGyFGdnNzNpPRlJ3TzGDSm+058qzK2ibIE6/rBY34oNB8tYaPHSgt7ccCc5eq/1RU/FxN8VXD0NBwH+x3hs/I/B7cRit+j0RCGqyqGiKJGyTbBMxuNp/TtY2bK9qWy+riiPjbtrHB7uclnxKgx9C6qk9gmYXlsq74eL7eMiGKoK1X9IoU2gPHpAYDsdiOQiTvpa+XRJgn9EbTiUs6S0NmNYFqJZOpFsNl0moIGRabybBCMEwoRGI1GAxWbWwCvghQ6xr8wQezo5wUgTOhIZPypEmA31dm24sX2m6Xls6UE2ByGLLz8pLC3HZ2dkcOn93ekcMQtHOy7Aw2o72dAWaLFGqKmpMu2ByRmhwRgUuOkCcnCqWxycmS2ARhcmgEh8rgpO+YJweLS5aUfisrs2Pl2JKFz/YsBG6e2SZddngwzW3CGxtE08moGQYZLcgbOxEaRAvPLtHlSMPOJkKvpIKvJEPOqmEBUb7+CQG+Cf6+UcDZ7W1MXS7bWwzoqHctATZSpJQqgTQmmVth4nVhNpWJ7uWb5ntml2hy5KFjoSH9oeHEFGwm6m6oL9nXN9FXnqETU9kjIwRGrNAF4KJzTBpg/q6YX2XiyyNwyMgIPDICC0hzuDn6geWZyRL8vaC4fNmewoJDMcC7veXLUuWT0nUrwCK/xWQjITid4PNE8n4iwr4IzTcNVF0SDVLTALM7tPPJNfiKeg/NFk/APu8syds28/kMor47ljuJk7DNjDwei7AnsEiPwB7LPo8lakf0fbxk8o71Dth7RCwayNnwtM9KImALi9Lw+FaUVkiAdKrDR1RanWFxfp1BczI3MiFBnET4y6dD9PmMgq/wfL/usEp9RPtq1RQ/nOwNCUW7GfCpPisJjy0swuLxltlmeEirOnJEtaBjGax4VvKp5IlgBz8Q0cSF0MeNYY+T6x+nJl+wLCA7O9my/wLSS3IpZWbjzMUU75mDtO7PWXv9BBiRPZfNF6741l5mZ0BkPpgtXfGrvUScX81lFhUi6yGTGKhL39PNFx7UgMA1Jpfsd1B7CXil04aKu22QzbJUZSW9DUBcAH934yvY+nsJ3/o1dmVrhtPQugOYblaZCfLOsmG2wHe7HZiVPWc7dpXlTSYHpOsubMbmbGXNyj5gR+ywOsvmDZmYZandH7ftNJTRGrvS+lXCB7l64Q4+b4fgV5BqXnh5v/xs9ore2ZJlvJAIEeP4sZNH/N9Or1rSBYHH1v4V78e/6vEHNhDrj0g8id3PX2tVCEE67prT30mKuO29/ubV9fCHt9eLz7459CQHAreSoBRg0aRAozeBWBfMUS4Gcx5q1Yt4SYsAskkLHRJeoIQJzQyldYbQQjJB+txBDwFzbPdBBthB7WLVYjDa+1ifu+r+uZJlvb0l7vf/517S1+9uvnff5NZLD+qj1OgzCPHaKAIH31hNZGrGlMoxrVY5GtvU5GzGW416h3g4KWVDIkni246vkbwfGX4nrq5+LzbM/rarqRH/Z6T7fXbNGgTVkJ20iYiLtRjIWVQbiWyjZlBs5STQ7FJ8xCg9qkS55qJ5xRYuV4YlWf8fEkkuKyOS0stIpFJqqANyM5aYWlj488/TZrOzk0jktIbHsxbxUHxnVENE2hp8rESWQSsqomfKZAjs6lQ4EVdcnDa3MgaZgkLpA9BcRjKSyUkOaEWhQMnz//A7OZwuPp/ThVF8CMz/h8Iq9APv5iu7jFrLiWEOSLCkPS4yIhaZrPfFLS92Gs+XjhZmoTuK9BRXrYtSz7sbAK4gD2NaGQIwQvbxeasvfoXFZVwvGbJmYTqKdeTrKmeVgetjACfkpZdTKZXpvKyaWhyFYhO+amiZ9KoaCvDLeLg/uOz589Lg/fuZRTm4lIHBKJNS2b/Qlu1raP5ddfSE7NeG3crfj1f9Jm8Am+E35bHj8u/QPtXvJyp/lfUNP7WIdddTdqQVm9DdLBamm0rdqRwe3cKM2s5gi3aksjWcNiaznc1mpY3BYSfYyjG9apvtcDQ2InB7iHAPk7fTbdcnggPLcRXTgQD4q4LIFiLeQiDhzReXTDETcZ0fMsFiwREaEGQyIpZMQiAopFg7jgzwRyZob5SLT0FfNDUVLn9hXXa5vvBBeXnh/b5d69JLqkvFi6ZtCUJTGpyyh8cV9wlFfRKpuL9fIORKlrGcKZ8k02XFi6+Ars1EosX6xLPNq/3zxjIioXTjtXavDo9rt1sIBLN1mZfd0/5/k5lANJf8e9iq3fuXu9ZpIAuTasDiMXojGosTFNqYhkszPmNgfxee0P8I1pv3XckrWXRJdUk6/xh+k8WD/uQfOyNX97nwhuqGaP44DjJ7ZT8D+CICPb+sqHX+EfvxcfsD7+pHqkvdl1SPfGq3Przb/HfsFucm9dqLyj6Vtc8rj6SSdktVRC/Zxr79ioswxVqwDopXe2bFhlD1VDgLiyOlYWjBeqqMMlpXN0qRyQ9T6jZRxmSQWNjbJ5CImBP0iulhKn05GUgseZ0mK9iPUPy4HUosP636qgI2p6PKgF3g0u7/GCAldnDg3o+0jqmn4Yd4cBBaKwCq48MXd2hUJFq/YVBT5ofEIvgGOFiibeXr21rnG/GQq/F120OCd4bdif8bD/3rIXeFsgtwxeTy9kc490oL4ua1ybrStuJc3wDGdjFa7m/Y8mzL9HG3p5FcQTaOPPHBjnXck9KG6sipQUUMI+Fu6Q218x0piY1lnMykOjTEqEIj1qE2uFO6Ni1clYGAShhAF3+5B1oXDyyo5mNd5zRbR++Z/jNg2yvVpt7WC9hlo1UpSDU6FalSp6CEjoxZDAZGIZWxJDLCnhyLIDuhoxvROnOrkBiUmseoUClqFJqi1UiUMoZCQSDsGER6jEEABpqUaVix+OsXb4nESWQYJDV/rhKlpg1Cg9i0ZgFgFGBjZIGd3d2dgbKYmGBZMWRZYCqvi+SxPEbiYlnweurap7TTE8bp/8HXv9L1jbOj3heTZClJCWJxfFKSJL4fnaSCo1HwDezp8+blhTHcGBCKioMthfmsaPivIuxTAPbPzPgXuggHbF+9ZWNIZPg48SNYQcuHqF48YJaV027qPy600QvQeUVTXvyhywcv8056Aek7Ds3lo0JDcLiQMBSXi8JwuUiKz1fJ+7MIeyzAngJcovJnreckUoKrO+528F2C3GU0ZEIAK5QTSwl1WVvBE/A9EjxldCSI1j4zoJbnOCmXHBmfsqgWn+cvNd+lhAXjWfv2rkAZgN25MsfOYtk5EhRSrkhKQsqTkhVICY9ttzOASd6cfkM/mO0oP0AAKjiAiwV5evg0ZIYP4oPhveAQ3g/d4UOQ5x8Gf7Bqx+AK0DT2deBdDOGDQIX3as/7+2EBBOED2tPhg9qvwnsf3eTv15KpdUMwSW0HXfwRhg/ikfBe2BTej9P9w3A09cyHYduzeAeE94LQ3w+tqZ8d3nQc+BhAg7IOGC5RWDGE90PJgw49zrzDZxHoHTvcDC0QkQF9CEFboQWVefv/R1EzVLDv0W+ACw9oN2v5Qgcbwnsfnenv17BmglNZ45opVfJ4mlYZ2uw0MFZawcMutP//XuTW/KRLXDY9B/VFrfo1FEbkNbfSXOv0HYAa5skBJLjj1H0ioqJ90+0O/l18uC3RwnZ7q7Vjdii/pz+Wc95mb0t3gnW+HC+xd9lrMQnFfnEQnheHJwdSuVAEoHPq16hTVXX12TqqMtVUQTIYVQ1X1A0sBe+u/G6QguaeUqWOeJA/CAgdHrlVb4vKrJJV9zWsAj+AZV9G2Yi6nqIFrfgpmv9efgG93qTqfbbB72kdP868/2p7ZeBttfV5oEspzNGXF7ZhLH8H2BGIZRV9egcS/qjKQinIk0tn1CXSMQ9Ahvy1emT1HiJHLN1OIeodfsFv41WNiHvVoWxc4Opsb/IGNVAxvZ7HQMhQ3Konhh6qjAfiDIzhSYzNfHhUUdOd3gJkzrjLXX4vMEg7Sj3I6j0kXgZoGM0XEtCZNtOMWryGG/qTOtXUAMUdNcM9NgzL+Fe/orrAvp5U9/ru8BwUV+MVWYCPELXArIVW1jRaM6pE84Y93eFsIK/OMlxMQp1S0ark6u15ZsZg/AaJDZXFBonixPzPZzE72epgaObmdhrfbR8U30DITO+aLK0J0orMdkjS1sQ89JhfIAPYrE/LQzpZUQD9S8Hn5Xq65RrRsQN+PlG4r5fv4Q3XNAl/XxYP0UV8fJb8IdusEEYkMKYtLsSu5RYJosB351K19ArtE2P8Q3SthV+yG2cGegFdhWAB+N/WdKMFiZUu2wb7vAw8lSub7hmK2JinTbQw41iRPbJ+Z6JCd/LRHuQW73OV/wwGxouEEIcuLFEbA0mjrcnjBdJXFloP9XbYrj5O+H38af4iX8Wr+yzaIfbLT3znxD9PLPTt7jvZN9aP6muOAx1fDiSdd5z6y6mhwTzqGfYaig3nDRWGoaFbznQHPx36bOjw0KVhq72E7YtddPaPZ6WQ7yOi+0j3Lef+eO6/59JDD4f2jCLO3WEDY0MXng1/Nl6++IOI2gnaq3jz3sqloUtbLz0TeS+ybuLoxJXTKJ84/se07PKnUc9Pj5CvRFef4aduvPpkrC19+7Vfnrn3rKnXV15/O27k7MrEwon1EyMT98Yfif87/kb8w7Nb/nblD9dfLiwXqkupS7PLSZdPrMD1Nvunm40b2a3XbcxtmrvDPee+cj/cCXe8e637/zwSPHQe1R5tHv0eox5n+Dv8a/67J+K52jPYE+GJ8/zH64zXpLfJJ8hnyOcYbCHMBbYBVg/7Khf73oyQ/Wr8dvgd8LutOPr7+sf5U/11/hP+V5Q3yv8CigKGAx7EEIGWwJ2BQ4FTsbuqYxC98lXSELQ1aCDoUNDJoGfqJ/XvYGbwmmAfH3qVMQiFDlwQAAgxAPT4uJvpWWiG6jVquCIZZapOqbP/GKOdtzoc1n9GBVk4Q8BPffETCDgko1IlqGAJ/swlTGHLO7fA/EjhcMtGQWRn8zVzqN11HCCpiyJGdfeobACC+LnoDIrOxaug77k4Fvx9LmTB9rO4IxUqCRPWwq8T75YeuqK40Fzdeu7DByLxCvZR9mp1p0q4Voc1tj5uPHIAoZoEdea5dpFKuWIJUljCheZufca6pec3L47OmfeUd8+hBK1UIWXO58m3fcyQ18PpwA8yGQ29Od/vHQomorKMGLjWspkorLKeUC93hv2bJgFYInIIfc611oeSSbMsFSbQqHuipjkLBFFySGk4iQo9FuffP88J9yhkYyW9WttYlIj1ZMtQaontX1yc0BusQGmd0ubqJtnG3pwuFr6dKUQvMK5myetBV7JFXGSCQH6Y7wjC2zaTV8bgf31vcgDMuzrIYkDwYGWol4KOxSXVvvqWdBCUJj0/gSbQ5ijK0TWsdbQGp8r4c9v5sgV7sgfAbjGDNJTW6NScMgnvbYV5XwtAAmilIT6TbTYPrrSn3cfAZiFNl0/ZqZeaPWEJWcAhTLZ15Jj2I9LoLWkTBe7m8ph7qZnqelKxaR2xwYGmrGAlUd5FHUwbe1l6LD1EQOLVlmdBcfjbtMUdCtvDO9FwGNHdVZBkmRWwm+rNNY1rTUtQSddLX+NFGDOx6cEYnx+D4fYjD0dSlYRsQunaGH+0jer/0VBNHo8BZlovyz66GlAd2PmzsNsZ/3xjdki1VU5pz5nLU22CDZ9ICT9N7DlJCI21Jrcrw5HyLlAHTvyhilOb79ouqw1cD1xQ/0crHl29k4jwVDcUkuCsydS7nLdhcHctxoW8oLpWBwI207Hdo6Vu1IJ+gX0NmF/fY868CIyQ/SWLQueZgcCY+R81xJpQiDkZcpjYSqkzhskWmXQNONIWQ7MSpcKLfH74Pbdoam+f8c8r5QQIV720akvJVJQHzQYjBRJrG44iVRjOUiuq0FcalaRdlGCWPn22WashjmYYPDKF/0bkJXBcflJm+6ki5EvMZAIHP2XUKDBE++yAEBICkaGuy8IPDmmu57o0PZDreHt7XtD+TTWkZf+S1zi3hlDfdGcmF6F8f9VOUA98QeEpHdUAd7znioYA6uqOoEqjh73i2gJAQ89MVak0goztBv1OFom8U91J1ewFHHYC6M5BSYnanYuXQd+zHIWKFuGag1oTXi2zJVPCQ14XThJwTyRoqPpimyp//UsUSjXJNT/YJ+qEtR+eJv4Kp8KjkNHBfWkEArIIshb6kE0ljq2wWhI98gAt7tfAEbVCdui/xHBWlhpSWgd7RHCCuw0FAm0SGDDtT/soK8vxNVz+hAq6Q6BeBLecwAQOEMBohjvp1S4p+MMUNBEJJ3krg5LJjJENoE8S/ogwGt0YqOvr/wtqY1oWb4d/hDZJUDEJVJt7o3NmEbBxKy1cYCTWV/XfUUa6ma8lUx+5K0lg+tpQ8wh5q5409UAjGKXmfJL4T8FLMzD1jmy3NfkzEWjJz/Z/W/9yKx/wS0WurU+yaZoKzO5+eHGaGSxEGgOF56tNY9AMltF5oGNhKXoGjHZhVHwKmabnY2ktAbrEsioXYcO0Je6oravZUf2hoX2KpYrqhaYE5dyDrw3XOnbOsKvGo2CzkNxmiucBK/5qC15vG8V56SUojegCJuw3+DHw3Y4Q5uHOo00HLwt77uFYW4r8FVN5JrGHJZwrvLTavSugiXdI5XpqVMYY7nFBcDtcv66eznJoJ4HZevHNgEZv4279LN92fvn7ZVWmg774rvAM92vnZO/2sXwPzWsfmCjzJdlXTCc9JcXhYJ1Ze+8XbznzMKpstbrOqK8uFOh7ODNZ/X/oQHoG/1BPYkJ7UlutOeRA4BKevkXSby8qLFYsjyk7mjCTIjsPYi4ecO8e4ncMZUCqGNRhbP7k3DQY/7WBg55JtZ6qIrnQC47LCN0El6jOwA8vmizArdZPnZ00esh2wL0IBWUugcOQ1BLKlQmvV5DLOMmY1mcK++7LQGWbr2IHv8KnwKPiBHLo4rRBnU7iURLpbEA57riiF3GeC8ACkaMwTTecBcnwcDiud1C5PMrVKbILywzMZ1iKT7f2Z75epnjorLb0L/hupvD+iqZwBDKsHlkUjaU/nhyZILSg+sxpk1IVw5Zi+0KVAmR1GX5ATZTqVryV/cWl30Jx7IXBPBSKMOGOyjCVbMRXy6x4L5BHQiQsxH016akw69yzhUKz66IOFoPzt/dd3pYNXawhbF+rQyf6otEKWtOFm3ru8E8y9YPLXzhnz+dtx9t2ojx5ISqhFltwybxy6EAFSJgo2O0FwUOuZ0V4beRbJHL8nu/nmLMoeVeNPKBJyiRY6XHNuNQNLyTJ/GapOk2ioV1Sygv//EAFA1Qmf8s/31ocUK6MHcp1qju6dAmTanABtEqT3c3vouFg6FVXQzM/HFAOVgY42zkm/0gHuJeT10CQkIbLzirWmt4vDZkGOmi27j5DOCHS40EK6hVV8JMSKJXMDehaQ51QUb1TxAmswx0eZy7UygZufrGkukqkJVTEGteFe4kBNxjK8h2af9z9a+uoqFHGDXpic9mAdkJeMFSjH/dOpEjxunK4JMdUkfK6eM3KoVXfv1BNJhP+iBfaD2QzhZJiFD4j8DglqFBK5rYUBXPuZKGorhtnueHK3IivCPFU6tm6pW6meDOFcsR3q/yMmM5zqFQY5DphaK5/qMeg0E4HkNdEKM3fLrapA8uFUr1t0lijk8VmVylVD7GSvQdA3s9mQpZ4yDXeACXuXMFkMZYkFgcGyndESjK8+j1Q4PONzaJBhDSOxa/bBUWq6x6w9VhzyMEmsm5DK0nl2ncWD1OVFykx56ZJLy+NIbdOzBWZvOamJQ58LqxD1xssdrWWrXwwOylm4lTGSYw7eS1X7baD1p2qKIK+gSMNmF/fFWcugIR/tnxSeN098wi/w3bR10otoOUm+hZ6cRhK+GmFobsvl2VAYPdNBhCQIoP7Zu+xd/p7t/DsUi78ke2SYLl4YfdzuGf0LQxiP+zkPfgIm3ldzFYHHlDEcVGo8Ipcb8r1Zl9TYhswRKkmeggv/wynchz45mOolgzeGSynQAoI+HAlTPgQ20S6IfJrJ7JA2iy4zVASq5tzTufdOpz79fNGIkAtpnkSTfThxu3GDpTps1mNmJZ8AJ+0gLOkcFowHKdsWh+8YCnx2yOFPihlysPIFe++tBJB6Vhg/0HBhJIGrLpQVMsn+MQAFvhuXtvP397WRI61xSXxkEvyekYzeIaOUBppaDZ/aHNUgmYioydb46iRVlk34uIITeJY+4QCvNapattBQfv4MVl/7C2/Z3Mq1vusHCnC0Ezjzz530J+/yNS0ukCntoNCA2ojFWjBT5fx7NQkByVV1yQk9FxIokxnzMuV8DHXZJVX3iq4biN2dzS51MkLcIKYdvKWL3bbQvNOqyiCPoGjDZhf3yPPuRhknGNXEDtTPx7Hd689v2SX9GF/RbkuEzqXyqQ6rnIZGUZaSiAqcpwY/2u4NKJ0t7dl3pN1oMxrZzyQa84njqWW5Xcp/o9BzR918f9iINMjIOZmMCyxCoPXsJ/pK06iG7bTBhnwhQDDXAkG5DmvTSWaJDtiGL7Wf7oTX1H0WDmzcoxtHNjzblOMYZQD66BNpkriQ8fYObPZmX/ZbTO1gOnC0FHvRHDV/eMvy97jozMn400ufbuNRUzqh2mhBpTjHxVWNj+TQMGG2rKkJYo/29Abr2Ne26k7l6NTBooKnSjEmopc1HDXMu5YZnxdm6SDtqbv1bgOIhKPD29MPuLZslH22/eZ7Wf8ilkbt/a+yuCZo0ebTsCaJnSiT5ncA/2uBvkBqljWP5zgYBXPR+dUlcQUrnVOaO7dDBW+KkSOOaM65uAHkSjK24oWWj3ynQjX34zLPuWYor3ZSaN976is92ttq/S3rqaWSSmJyFe286z2N97yzOHBwgoGZbhRVanPwdu6jAh9fD0tU2lmmEI55bxChfhusgY45QeQ1HaC5Uiip5l9wr8WToVeSGiL1Z5jMgi6gBLWII+EOHUMh3LToPEFmoxjgr1AQNKPYmKS0tdAflP/HbzMVcF7GyDBcP51vJph0reaPfa530zZxx+TB0x7NQEYIICLcEy8ihKZdgTKV/dxt+Wz9APR/Gw+7Dva8GPYg70nDjYf9f/43jfHHX/b//nympUXQj59Wh7pZx6Bf+XczLMcBR+7V5ejHEsx4rd4cAE/7jf2ZMqxuNpbcNA2VQy2BGWUEGB2cxdtaLbmHpOAEm16Rh/XkaJIJAXmDJxY7lI7Oo4pVsVN6IU9FR3gtQ/x/nRS0D4WkBn8/e1epENBfM6sj5fy1nz4nhuwp8AKYohiBPnn8/jeOmMJ0W46QMrXASR0w0XirmcYiKVcQ6BoSP5DmZ7+tDPnKOqVYFo6Meeo4GO2aTo3VTmr4HoDkXWjBfOO/04/7EYFe2/XoASSauaZ9uI33sgb0DrgBCQZBnw+qq9zMPMIk7og/pimM8wlxlU+CpVWRHeHp0Z+jWVDYsa5TCLDIGZhVAUSrgCaSAjxTq4jH4nHRwbgC66xWbJalMGUc27xG3JjWTznRFcPslEE7cg8sp+rBZ1md2cMNgMDi88URkt1N0Dl2yaIopxB6eGLoJyZJiRDPXBeI7fhHYEn/16PA5E7BVHi8dZggg3vqPN5/VgM5X4KDb8GKWVUKSyo/UqNkvb38f3gWR4ljvfuV8fkSewkH+dbVE3ca3mqY5P/uwG2xj/L5UjBKooSGP3eObXBfMJvKR5F01Z8cTw1XE/NaPzigKyFkp0Js/6DryEWagihu1u8gULpc86Y2pjRlL4l2T6KCyH8d4+TKnBtw5WvMS1k412GgWECrLGPcxSuMr/6OX72XhjHNE4RqGa3jp9wR7fP13mk58LpnXcOsCWudUNkRIsdVZPYLp67vHufhmN7qjUna7jXpgIvmHvAJTL4UnBDl63Iouz0h4o3huKh4+B6wCJBxbt1LJkhitBI4BaqM4uU03gSEm8d65RJNNTbQQH0m5rg8yXmgOKiYBD8bJEOdpa5s5kwDXOI1qn6edHkcuvbGmL3AQxnqGpIc8b11FAx7CzMtKNMJ4elCDoVGuj/oqB+/O+WQcNpSvgYQQiuOs7e6ZCvMmL1WCwySrV3OotSatbxz9jNS40mHztGAkLQorOQZQvyt0EXPQoFum4IidOcXGNXI3iDQWDvpcv0j6ONpA0K9q2O21te+MRUeQ2W+qrb6k8VhNC6l9cUo6AIKWnuZsnVZWZcJRwmK0t+UUP1VFyiDHV0mUqlPCn1LEJKZdAveUYfr/uuanJno7ZCQSJxmZIsv4uda/Ujh0LemTjfqw7QEBNudpJc5mAUN0LWKJqzqFNNK5LZnwTse+dhFJtOmmcJF/vvQOo/POXXAVvXIDQ+mGJDTw2K3AblpyO/Pe13M9BWGZOx/LCTAvDaHnFaqjILCkVaKrpp+gK425anudXzpMFnjfJ/jKxlkN9IlAgxRVqrnDqXcftgrgS5Q5LTie6XBOPM1HjiVKjAerq7cdKnhcpTZ4ynqlrrcIPO1KEoRycKtx96JSRN3bP2Ts7NuweONVYGZ8fJ58946RmuI7kXvC3N3sMbH9Yi1Jt1KRTy0Blz9GDq91KTvePylsMY8+0CVfXcw3FW+T2ZTOUZ7BQfR8uyOC3+NcB+jDhH9aKAH5ODA+LjXF8+wnfIlv9wB76/rDurOfsk1UhjNxsPBGLZP3udtuEWiVJqtyj860XpImpSwsCg71rrHNTTSEG5kLURVyE6d5k/sZX5yqQBn/c/1l/PqU1mWkXvBdv3HmWe9OTastiWJae6t/4jd8lTY4NtWixmuHf3y5/cXcX/8cNXxjVlvTfCWL9XdXpPgusQ/7tiP+//ikezj0i/kZ+dBceGoCxXd9F2CQGrzRTVOF0hmkiMTM+/a+Wj2PiF4CBqD4HTjaQJna6npxLEYwJCt7sYgEZKLvM8xze1nN05GT3uZKh9VmjsXHLitfmlxzvxpQgLbUrcQcGv8aPO+OXhCaaMz03LS326o200W4+zK8mcfYb5LmdQihvyZe1cK/rWW8kN9s0wx6eZH8LX08ZpOZW3DM5bqfiEncrSwOd8Yfu7yI9Ge2trVUHXCF6GZiIJTCLXgqhrRN8FmePE7GJtI2K94GN8Lt7SJYEJ9QhgFJKYNpGgZzmBNgxU7mzh55qW7f1NOXqJfpFPnsS3hGaSgT9xLNIjAALa7f6jyY0reuXuBH/6pKzMrDzCzpUFOekc03efp6dUGwC/L5k4avHYS2ZBh7fOXwX59nj+nswDJgiS1GSuTLADqZQzG3YLsELSQz/GxYy024wOqaTeIzs9Ed6+LOBbGfKfC7SLLIyuiVSItdjhcRpVYQzufZ+virauFCpDWaq25MHBcMvvzIcaEjG0KL+DKc0IkzRtFLiCxlEGX+xf2V7VB2tWsMGElxMR2ofJFDPU2jtd7CYJU5BomIk0JRrTRNglzC8TbVBG3rY2ehH57QgRpSy7iiWbtxTeazlPVfiai9l1NDLR0ZI2Xir4fR6PJQRjwkOFVeA3a2NNwN+lPsPKQePYfFP3CiHWiCG01xvSjA4Y7qR6nG6sZcqkMcz7kAKTG3dUL04NalQ6urMeet7jcbV5fdEHyXyeEXQgouHUSYZh9S4PZZ6wyRW1LfARkXYWPFYKgYrFq3oap3kWZg3F35P3FKVULYahPsuk+LbF5isSm4O4L+k4+/ZM5dcHKgaQ/a+1/C4qsW/NI7oxG4/7WyTQRoNtS6lUlC6SE719inNp2EaLdyTgrwn60sBBm0IMVremuFo0ibc4wkx9cegViyglcRhPpJ5Kzzgt3YMPSr4DUe7n0jb8CB5uuHiwfw6L4HrgDwcaaDP/H+mlwWlT++eQb0yH/9iSg2xqn/pihww6bK1RhhoidbDUmuwq3qil/U6Ve099onf+kGsz2INkBdmBvghVo7ZKWbmOmZzYmbY6DZi+a061Sg/MEWS8fZWBSF3LES1E8oJ8c7V3yAxKWIldzTyPgDc+RgxgNGPmQmjXYZXmHz3urwX2O+fOwJknSfCR8LVCXYrgwx+096BMhIF4H8K2wAIaQKDZMqVlzIvMGIWG9lloD9u0s0pE/Y4dCD79v/snp8d/tTG8Bx4SGewCO8b/YBazU6pt2m+z2SqvXf/cf/IQrE4hcwNlNvZ6BAewZiLbnUEVzyGvVlfDH6Uqb+QVmsByEtDOOC7/708aOU2EH2oiIm0bKpiCALuMRitr0ihw/g1lskPhBGiEixZH8aq4LQovt0t2gfUS6WnT4XySHXMtBboFUIYPnS54pMAYMib426V0miRFVHbeEbggf/Zdeb5smtb+pnkTLK44QawdeWsTt5Qq2MANLFNyJxV1jjtMXDN/PB6tnKTTUVvHHDVKGW3OkUQuPbDv2fdTeHlMINVXMlh/3SoTmX5+GoXiQdfk71lQ1uUtCmU7R/QCQlhnb+z3Dc0j2H+kNcysSneraUWbh3s3r4o0DJ0WVW4ni3QSyyV87eSi/AJ0ozZAO6A1XKmOiGDR+WqT6P20jgRkmrNA2CkOd32YZi5w0D5Us//7Nq2J8+RweikNQiHae8qygli3gzaDdiNjuCPSAK/s5odgS7UHwfuWEghwn7QAoLqggraqCqokooJ9vsAwhHEHgayC8SY+0M0bgUFpMbfJaEMIB+OFpxKxfbKTZ9RGj0mGtPRTVSYPaFDPQAa+EDGiYrrc1Cg++fZ5LjXP+2wUhC/yrOmvzZnSOGdoPdjY3PMYbjw9sE0qU91021I43TmvxrvMIJdJNOPhyJGma7P4RkIgr1ygd47Tu99ZHLyfMnezfzdnE9eV2Q02T91BwaEFzR5Yhzs9/KqReS8o1b59JoazoWQMcVEbGzR09N5895oXt9cc8BRsbo9lGVxegW/kKj9o9OXcWgCPwZzcbPH8AcFnZOWUoggZw3idXByabTNWMdLIw75R+JSV6ElqvG1N+D2j+mOo7lO+sfZ5lR8RuraTyG0FXYfucZKPt1eI6hLIrnNS3kO1JmGCThjWTio1hQHxxkOQLkzj/GV7+44C8uWcWM76ZR13tS7ghNZABGMKt5jZmFtLCa5VFyS0oQ1Chu/9LVdXgP7uzIldHO3T/vgXUPM01K3/CtQN+GhGET/ng7e7vnrbcdfnfPnN57cEb9lHP2aN88tO7W0c3UNIWMCZecsyVLdmjoRQXkxJgSZCwofsIPhtIyBquGhgqNHV9Qr28amWkm6EWeNTNrTd89HkioRvbX0ez6lq+at7kDpCoK6d7C+TOoSnoMKUiGWtCUL3YIzQq4kjHN/+v7XU444W2q+dWse6laDHNCz19DuNhrYgXHmwqEKdoPXQZphkdrpEJdGM3wosY5SHDkLYkUbWJLmXWGvopMeUNaoGlJxQp1HSrlzwK1MmLpmo4WZ0LlyswUs4t3qpXzQdZkni4BEy4jw31jxSmDyBVQ6w0QmLma55GfP0YZMnsmTdxVQGivM9acX++4r48sZTw807ohE+mYMWFtc3ym3SIpxFfkaknFgQ+H6Zh1ZGZsCLh9rYS84l5Met0jPV17ya3pRqvCmU6LNGAqPsHvdzlKhZstJCKZYZtfYDNUhZktxkyeZNdaK47CEKfhCiH7JHDRWpBihcpmdpzpKzQmyFZpVQdAva4UYyDjehFa6O308o3ZRSLkR4UZYBgVESn41Cn3zuq5vi3mC0UKKvJ1C6MstZyUWCF069zb3k5vmVv874fj15+9JSmUe8t88v72OorCHw9tHrmeuKK/Rbv6UYlww9TErtM7qHFNapSW59SGr65DsPTXcq1SH2UcyIaS6mjlkcJoSJQ7WveIdN1jCmYFHz/NJQ1EDWNhrq4UQOdZ4kEzpItZR5ZFIo9zUdKkITEXW+HAx2G25OisVMF132wdt5pu2IpRKKfxGvmRgGynk5Oq6sTcbQnE052d4TOhRaFMMjx9RRX44wkDMWbw+COaE7PO5jS2nRKmmYU6KlRA5mf/otf6/IJnOtyZ3Uf7yntGwsXdu1EsRXO9LnozFb9Go0jYYZakk40eKHT+1smFP4TcRETclEl74QFOVz6AqM8UAPUkuVuadPPSPCprlkqQTmSpkQR5tb8ItR17TPWdu7GwJHVHk28eNljdiDIjTNEi1edGmmGeu6l3AzkITMNbpkoh6+1zQXOFfqwd8DV/q8x6BrArpuBPwItG7B92o7Nmr/9RqQfgXSN4ENVjFEgN1t03MMW2dRqnoSKD1BtpQ4517FlFdopVJnhNKQ6yynQxdKnr9QVTR1zSyYYaOFrYmaIsnh21HVAyMEcFFlKpWmjK/KA5fLCobGGj3XWTJqKRq+JCjpliSv0HhBKg1HKisivKSVpiN1chJIdfJ8U4Upitp4jUssiFWrYi/h0NUVp5B/ESBUvEtRHAkX0yDn6YqdgANfcKU34JosQzsR0Vq4h/+lAPPZJLgu+++vPUODjh132FQKrScQejLDjG+701AZ8XRDKzW2hnH7IEFCzxR07ZL4nuXphlrCDDJDiN1peo99pbUaJxKxNIeIi1hWYRgEqWrRRIrISYYoBh1Kkodq2YSXSK8xq1I2a83LKeK1a5LQmd5HCSPQ3/TRxOk9NpmQEGM0EZebSkZ06MqlkkEFtRlRSq4tLVTRYK2TZMKt6K2IZGLMDnWHHBT3FSkaQYIbJ0ahgRldJ+8oSkXlXstLYDVLJi22FE6lmpks/8sIjmZmoEdJmKFRCNteQ6FIn9dtepzQf6YGg20fWZqXMJmYRNMs4qrpt4W1Mk1P6Cr4lSdA+A0u3TT3boVV+SSVzZGc5ClvYxfggpVa4INveXZ3SGd+iin4SUTGRkRwZxQ5XZTxys7Gy7vnd7f/0eGbmxWFaSO/j8NS6Se797QNGoAd9qpI7TJ8IfZRcU1C1Obadfw4h7GrdQa0PWNrATxYdNSfc2jH93OYsFrvQOu9EfrBd/VPEWpu6pWFCHCIVdtBdVKnJaMLGZkDlQiJ7TedwhBljXKuchSyWpylQyCregkl67v23J4eUIxuBA6ANJUkK1Wzi0EksERuR5Pu3YCL71omOGiSqRrNk3P9HD16T+fQNrqxEkRVd2CS+jJfJWw8NDxDlDSyws6UGlH+y+wfe54JuCGZl+RYEbdenLa4vO646d2Zg2PLIfS9ku97nere0GJ1ItbACdcxhb94GwRTdVOEX8+wIgr1QxsgDG1D8bD9Wr8u9MUw8lWyCSuy4OSs8jma/Fr/MgtS1BTSiiZxpadmykY5V0tydmWElHU9pKquY7e5OO1y38M2XBLRceVcv6wbyPswqNityOcGlDV4ugIbjZihQpkGEerLfLXJWr2/O/BcD5gPffSoUTcUR4RaNhNaVFWS2OuseXfsXt+C7ZmCifJLeO07r0G4oo3OIVSxttV8f1p00KyqPIqWubVlVePLR4zrsscOmqwmGQRxpWN6dU+dO9o0v32KsOlosbHwdzLqTjkvdC/jq2UGEs5qVoqPbebhr/hkZ7AdKLfYJwdm6y/lquqTfEM7m39rJteose5lbkLJsISibuXudF/jXKJ6FOd5TqnXt6QGYyazvIg/t2eGNaUoUzax6rEEJdpGUTfZbHi+vfskax2vjP+eWgvuGD23IusK/WdrtCmajl3homqUIMnon8iaI0OxlEKy0vxaP62btt16vke8nHV7FxdsSD9xS4ZAr1iIK+3DNQrZlJHVLGBZB4kudwxXGIzUlp1RzN9d52IQh5W6A/NxAvxOIkmAN9jJOJwl80JYYJxc39UNN5xjPh/0HneM7wtMJUVe4J1mfKUOux/q4Dw0EhnhOBpCarSaZavh6KUMrPRuZ62hkm6446z70eUMyoya6WBCBJHPlZUHh0LQNUbsYaAzURq8Ap0oy5kN0kcolGuSzkRnw7F6uM/hLZDsph/oBOl8y5FR4HW25fwjyZsqo3KK/t/S+QdmmaMf89xdB4InFkr32hjXBb+4CO/5xUmOHbIpO1YFC4R1in2Wa0I6pnhS6fM8iiCskbPTMfTdSKDIZ+3fXPSvwd/y7dd9cD4f9LRz1H8JFLoe2EVp1p5KM3vA91Nc9Xx5+8EbgpbwbINtlr64GRmRInZPfykyHHA3KdwqaLiVapwjlwMh+PoOUikphJ2vwJPC9RNWTYCauvSWvZXeOsYuGQV7rS+WifAQwIiVaoGWfleh8xZSdFqGTanaUvP/1A2IDLo+Rf12vaGI4VoUpfcrO+tbWtXWXTsboVGibhCxgpXKrdjTdWoet4FRVj5liinE4C2/3zMIDwMMQzm72YlCFe2MwNUQ8HxJNNHYoG84PLOxZYwaMwHeMORCFiUfsZ6JcTUuuUOFnW/a3c2NKTbtUbmIZigC8HSimcvrsXJmBSsWU2LQn/aSx+codAumo1BORSg68bQ2tFCPwke0zkE401qKhV67gMcLB7oPjbiCbbk6pHkFS+O0FdWs86NC274UX0ZlZMnpHT2TWayuK9CNhlLQAZblnkD1GmXHsMZJjGoAtRGUN/g/b834Rtom3c8rlM2cQgbM7vmNzuMOTSyII3X7yv8mDRd2/nUlX6ZcVo8KxDpC9PQQLrkFIk0XZnWeU2Hf51BnQ42YUTB0+I1vG/rAbczDqlFa3drau9lXtOYBW+bMBOFaCY1tBWHFCPuCwXkOulGeusIco5I/jhpGfGEk6PVIzZ8fhxoNMyg6ZTDA7cpE52N/461pjiLB9ligkPTB7aIe6wOVXELi+qVE7uIGEOuAoh5yzNMiqoCBdYephI9ZsjV/tWxbahCkcFOA6idkArqNd/Nw5UnwvPSs/lTLuFaYioyi/oFxqSmR6h+E07XapSF8+gqVKYcIQlJzyXmU4hussM/w61AiK4qH8W2sgW6iFD+Rb0Bwvm5AUhmuEOrLDRTdaiiCYvev7PYkiP7ILWsVCiK8DqBA2dLcrb6n4LsdpvECeze/kiJ8N0Q94bXI5Xs7oVPpkolCigqDweY9JmjhEQBECeF7H9qPZzFAkDNM1cJi42+JgtrTZLAYDjgOW/DqD1loIqlst30VC7MqeBG/aJ7WGKOgJwd1Jhvb2OC+v46B2Swh2lnyd7wZEYwwfO1Kq5Rco82DRocxncOx7H52rsUNiP2F2mJ71veCqgTvXJy1w2WpmNVdUVIVWIkRVRRP+h94phUH09Plw9vNFnXAY0VviXHAZU1g2WCwWFc80QJLj+JwJhvE6Eif5CKWvU9pKLcfQAE1aP8lSGsz2JjZj8+3LwKDVoFlV5ByfRytxQUvxTClayg/WEVfXdityaXaKZ1Ii/hgO4hMegmgoor0MWLihuIq16Tmf4E6zGhx0T6Nc9U9TfN+mhKkKPkZ36X840uy32ysnzQ6EsuEh0/ICsXi+jpz5nrxaIkntR7zQ8l6QOFh8qEXftHI6UNEX1U4wmVCsUjjM9E2IvurHUGd5hfuEY7KmuhaTaUau59mV9s9ogb2aS3baxrzYlGYhB6UfDjsjCofMyrdx7EMg31UoLsnKxNgfY5nK0O0u2DP2BnsfNk+mNUe1VKWVC2sB47oCLYkd8SfRLkQA4xyEnGKGq5Ej0/SkiKqtRJrmcG9L8odElZKV/y+KLzs6lsXe0OyHCPOJY8I7vuTwwGIlFmDJytnyG3dAkpnbKDntxJCjE4S8FVFjoRto+x+EMcFH5PVsM2SQqG89ghKmdAduno7un7T2xBgm7bKkSxKXub3+10Bb0GtHhBQhsnCiVJqKdMbelZK7W1tgoF/7J2kVDs6jJ+eJNtq/PxEU76Ymb6drV78JZsvq7AyTrcixD0s8AZ+K16NiJHeP4bZtuFv6ouQUPucnN42SRbJ0/KYqEqlIlwado7ZxKlGUa4RgpXUSGF9dq1F1eLvzrBG8ZZaDi+vzHwZtOTDNqmi7S+5djubumZypSp3OHLuV8NpXF+OyxyjFfL4Wnqzc7MzYXMsYK+8WcmMPrlsJP0MKUjR6PDnettRslpizGN0ElFMb+iwTP9QcZuHkffM9pF4mE37lSZFfv02bf1i5pdjyWik5cfD2mXF+QzyaAN8Y70q4k6rRE0aEqhZqThRUYC/ulGqX+/JqTXUo26F01wDyHTGLS0rWwNIowEPblzkb5yXMHmuakzVQqa5JKelf+ieTHhlC8Tr291mkRRpsnTPL7bNGhrJogXiSWgCmZoZsqWXF2Iiy1/HajSp9RDCTyqYDk/i59m0HmuqPxw0/szhG6c8juoaxnOM3sCookLn4psn1Qe6dyh2xZdkVOGKwBlyZzp72XV+0tlA4FPpIlNhnxYLE1Z6h+6GY1rXpBTPs0ltthxLs2zEnzl6PhYBnorB8LTiFlX0xvBhxtRjDMH6OPvEigQ4psJxbT7ll1BBaSHdSmpll0HBMKJvOGF/cm276mnG5i0++eWi6jqDPk7DsVU5K3TjzxBTtI/u/kPodlbFM1y0idVTm3OK1WgXbqB5Qm/O1ogWG+TIU6B9qtV4himPTwQ8zfHbLeLmTav8+ON+6+Grp5MSzTNwC+71SnNZuUav98u56PbR+mpup6HNF41E1eNkBFBRgogGt6i11b656EE4iqd0fDY7nFKiVy7BO0UPl9avmOJcMTAxmTPgydIGSmb/FuVV1aBFVlU5lVJUDVtSm05PaYgaY3zoELcVRBWd+NH0W5RvzOe4EneoIhaGG4txrW2qDkjIpA5zpowwtzKrr8wOBAE/iTlV3eSTEaZjzkczp90M0t/6thqnJmpAu14cjC+IyGPXpNqNp9N4QYpL41XPBuMuMINtgm8ui1TFVbSTWYfB3WPKJP1rZ6bU4voiuLxVuNVRPuZYbDcIB5NrhYJ1kvCt05JBUBx+4xwOy1bV0PWGLBzMox85uxUdDS/gHAqOnlMosd4K4Zz2ZmdEOQFw+R6Kz9kKeJsu7D5MfptQga31tk20D2eymEH1RNBoAjMGxUsBUixN2GgDwx33ckjU2xA0oqD9XTIeeMU+PNT3l4KJOkMtqwDTqdyLRVUF1DVnHbRXFoZqtU9/TFIO6fRU89ZvyUpWKNtXRgDkag3lqOBLxtZpib5P9VdSF3U0p2WDy7pZeuyQkYLy/mcEHTdNLHJZ6MNk/rEES9o/tguG7ZFdQdMB2hDeNLGy0Wcpv6GnU4TebIVCecd1LrK+ghEOmsizJqdUA4yjidNWideswPW5hU7Vx9xS0+3+MkbawNraqBWT3HCWxLHnA6BLUAJ26Nn5RVOJ9HgS4USxR/CgSypHxI7ft0QRPXLH6uHHoOSCgBxpujQeRv7KUZdwzrqfE3flWbCMSbuEmnRJ+PkKcxPprdTW1fecQIJ9y3EPN+GhHZz9hPAN46licRgzZfHVoaValeHfikVe2r8qtJPwDwm/A6qV116CoZFEnx+2IFAuNugopNIbjzD2bwk7V12xvZthnohKDT9FPNsd1qxXG36coV2N+2VI6caPCc+8fxuiHCZ7HM1aZHbPNMxCqw2uc2hlDZ1kTOCCaZgrLJIlPhAI6uig6IPDsiE51cRxfHPLDr9NlcW8vYGrozLY6cmw6XAs+P1HpEqTSk0YM18DciCrYCWQn5ZaXDJb6R2LxvZQLO8kCU/DwY2F7u4jVy7a3b7FzZ7VYnYM8srd89CtCArt6flY7IZ0ZS4ZZxVMdZ5ZtpZWvKyCqe3LKaSz+7NVrJVG22xomu6sBHm/W6FNI/UkDAaiINxRkC0hvRlIpK3TO7R5gKNlGZcqKN1pQgsRw/aL6xneJZSKrDZsVGW0EVFM297Z/PAx8Yaxxg6TbPZ/fuuYqgK9nOysk6AeY8Tie7tx1qEwzFrmhHi2UHi6uOfWeaXbgphXV1JAOsRX5xgoVDEHWoxEdFrKg68u5lJHm9WtWY+pY8k4+q/sVMQNOwNBWJsKwnkX66DQyXE+92Z+6g6FskXPenroZ3P/qI8IyZRWEYD4IIKVuGt8aR2DfyTQZtwBRNwiY3te/cawJBaJRAnoeDW5GD4Mddzol2CoONhx6NYFU5Xg+BeHJbHD58xT4CZwb+P+d5Fp8kEg+z+o2aMmTwFNBfU6Kd3KDv+KLLqsVYGuZA1ACOKsgx+k8OQEPG0ehxAmBunCJft2ufOheWNbnc+CH7J6sGIGZ14BZ6d7wmt7+vZ25+/B73evfrqMVmde31eOUgVmnOKAS1KClG0nccIdlT10rlrgxEQWRbfRaEXbG/d/zBrLyygU/FlQKsBLJyC7r/LOHZWThjYWgeqTmmw2YJ4ltaclBbJLb4IKuVd572VvDf01cmF9baPi98a/NPqL0leUwOD5sxWv38tNfgrmP1+yHAXFt+jCJ0GdCSJpS5IGXh8zU1YukPnyyzBwBrPCr08XP9nbTEsjzX+AVR3CQ/y9NW+atVjfB+EZzx8+yTeBslEI15euxFzw7sfmx1oNXehf6W1/jcWT6XRo3t1OUfoyS9GCrHq6z/368OYOPCBJXDKcai4UErSTF8YwYS4T+WDnFbeR3It1Lj23ODeTrVDIoZbyYQihM509hD0Vp04SwsOQ8qqdNfw3W2py29+WlBS7lpWGEYop3D6jPCWhoC0Zv4JLcpYBMi2bzQ+Gmz9EZ/H46YC64Mvbw2lPqd+Mgcrq/GZjLueXm0AY/wLWDK+OEksZ0IRl2GgJoQyeFcrnlVqSr/PvuBvPFy2QYSuMhaJNm7pJfGumNnfv9uEKmlPnblGbTT5ynRUyiI1PuLES6AWCmZrCPDQZgzNkXC2KFhglazog+dDfjoBwhhNdGJK485SL0DIn9bAQkyVlmY/dHLxZoyXV3DaDOrw7Y5U+P7ecy0FrebmdvIiH8B0qsppWXk6BAWGR8wXfqd6lSRAHBqDYRseI56P/CfWd0RRWUtd7EiT9S4kO3ITmnjorRanXub4zPhdYZiJ5zWhdqpPWdG0SvYgsuA22PoBmP9z+EvwEQgVk5ZDz10ars6aEypym/Be8tR1Gr/11C/hjOGH8X+NfH8fP3/cIv/7XQLPM1j4BTz7Y91z4FJ4Syng2L9j3q+Yx330NY/wgy3HoI1Er7A+xH+dXkG0CZIuveE/YzYaSHua5Lw7CTI5SQ3QtjK4fC9fCIW9V3LHIcROnwbENokj3EsvWK59SWMKaRxSCVU1RLkM6eGUOKLPiJmtNd63bxshYxiq2YSwVhRiXomEpdI1FcM/IatBRM8HgxMFyMeihHJ8NhSqcUp2ibZtISAcD96P+SOT1phZKUiF72eyGNyo39bAiOEo50JrueaFBQq3IopXZT/cMjfmxJs/kPhJY3hSHa5GQ3uAqacHRSC3rGCSvUU59XACZkP8xI/C3r3U+iIZF4RvaoQD2yHEd+tnNs/Z8lSmb/xQpjb1YPRWCQDgrMu9HmMHeqkgYCCVlM3tb/9k5dtw5BtJq9rgD37u/gQHqmdaeS+uTUyFlgSuggy1ra4Jeo6qyujqjWdof0WZ66bUUweM9cRHEgstaRyB24BuyBLzdiJe+HJNvH0KZu/rMDgqkIMLOOxQ1aA64TBROMWIlGJQZvozFc0k7VPQhgiowoy96JWB6eUlwzWujc6AWxdqOd8yU4o6LlCLGc51VuXr8l4yBLhiOBwkyn2r5i3mwjo4l26Ed7R6bT1a8ppp10+kmIHeny1HLqh01qv1PIs9jiVzS43bpoNe9ao9UgsIbUfh/zSSPtWMvey36Zmb21GltaDgiJbQEx5gC4/RJEZvE6izNU8m9Ah8zllXC8URyssAE8p4jWV6QQ+4/Q+tP2LX4htfdEg2DNeq5XCSKLMuIWCxDY7U7KcuKVzGniv970yiJS7ke68Sa8dRWmUGbDstG7PxobzToLZby9dguvakyspZSfbZStcSiy2E/TaPxSxcltr2orpX1ci1s3CYQeh5/6qRlnSVk7vW8kINoYZfm6o94D2LCDFVHRnqVl6X6bz7atXIFdb40V+zoMJ8HsmMhBMkJ1/2OZkf3JX7pC2LqVxb8uG0ZnzvolxgHxP6gfzu0qunL07lKwCaPHjViLH3YSYo8gWLy9KMIAtB2N71gusbnDkv8344y3gLgk+3pKwCfrwprmmW9QaK/qgNQQACAAP+fiDVwYk1eud2TANJ8Yy92DRmLgOJQnsy7aQ7kqkdhpAh3iIyGjw2hXKcyA2rk7UBMcASEGpxoNYjLDlm76Piov+d6/ft9NHOBQr4uyfRaYE7KUaTb6XNk9EesbwgjAMyfY3e0nBjf1zOLXX+K6hkPSqPDUnfJ+pvxJKrGvCp4jSCXJ/Huo6hql8LKMgqSoWYUN27xQ5VNoNc/Uzzi/Bevp0jAeChfVdykr0Ha4/MFVHHwbjcqDxHSCxuDyFwwfpIy7YxtFoG++k11zDZsBNmTSbNooBTjfoaA4UyCO7oXW9ZSx/h2x+dVZuc+kivHnjjZO4zQ3E9sboSMM41dRM7MShraQui6GAnFmivn5NlR7mEAlP2n6+srcmMG6A6PRBGtKEhXqOcYMhBKqD4atyyQpHBMnsZ7/YQaFJQesho4GKtZffUHZC4rQSSjfCEZcrrFcLsZQcU353QVQd5cFu6Mz8tquG446OghPVwuANMYTM1ZFKtOLtaojoK8WiLWv2T83QqGDZSjn137M9epEXYpervRxKhzrzGtN0GFbE2rzcHQRYLqmgZH4hNas1FGSsvDhwwqERb+Wt8FMJSHVKcL2TfFSLSsU5WtUzZfyCZIdJGWPcRFCUIpOvYQP9IBZCCAxSRikIJ2/i/BvybEXFBgMAHgvrCegZjkSwhGdhfK6CyCYZ2ZaIgyouh5us9GjI7+HQRgUFoImF8hAJcaCrhRDQOEVCdaIyukf0NexgAmcRoOcB3BBGaxGQEIrWKOfcTj4hmOeDgGwMfFZwJkLhMit5EF9mYS4c6TGEdEOSTv3wJ27rYLnem1YnKvr28YJi3V6nNN8whsb2otLWrbbpWyjosjWxbX65ZIRKnfb8uReVpU+wPrvzYVxLML1Vpff/BN2C5M1ajbiVYfHytdDHKkXNRYCRfTa0REV6E1ws2WJXU91t1ub92lN9bJWOuMXsdEl27daEWjuzWq2vNNBeOjaxyqMZOaaw5GV/12C406s8G8cDbCTTO+l9yxQCbp9t2SfQra7u1sewY/JDQZuGgUBvXkysIKDXaT7zZKJrdQJPvBmd0RPmmhIsRitW7M94tXk9vtRT1HxfKOYcd6uFR56Oe1PlrTyiduMfX3shcRvcUhksv2ceAog5M2MvM89dwLzly4knvpldfe/KSet93LfN7eemeBD/a7QmmU33x+a8/RffRJps/8jTXOeL9MELiwtEWWWeqsIMGWC9Eu1Iow0lm/Y+dQYb7Ila9AnvCY8/t83pdRSNFWWm2NVc5Z66oYf8SKE2+7BInWKbTB+t/xc6RUWippTjkdYMD8pwJpP7PnM19MEjRIhwyIQyYkIAuywW16eugVBxpBY2gCApQpqMxkLi6mjJGydAFGCVt/eWgbDnTMTGISPK65bioWbGaaTX9gqj1yw023lCtz3l330CCww6TIVjvtsMsms2hsdgdDfLY4wogOOipYs2HloDlKTYm14BLKQiKJJZFUlrKStWxkKzvZs0eA3dTqNKhRqzFwMGs+SmTMK8pbUKhVwCMiEao7Eo25SQQ8NqIjSoq9CRyOjuuISEVKfYhoGEYs0mnz/tlJTr7035No7Db5S6SKInPpv0ZJTGr2NNy1DwXn6TiVRndnU+f+zV9tcwQdvUBovKy4UL8I1T9Iohp0rE+lDqcPHksixCKZUViUJ9ZpRJWiuLBgMSGkI/BloBYVKNSSheGopRJdwR842WS5NwIR2HQ0ZmLWv0/l3M0AAAA=', 'latin-ext' => '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'];
}

/* ---------- dizains (kopīgs ar admin.php) ---------- */
function site_css(): string
{
    return <<<'CSS'
/* =========================================================================
   DIZAINA SISTĒMA — "Fog"
   Gaišs fons, miglas gradients (#EEF1F6 → #A9B4C6) kā sniegota nogāze,
   kraukļa melns teksts, galaktikas violets tikai galvenajām darbībām.
   Fonts: Urbanist (OFL licence, iebūvēts index.php — netiek lādēts no trešajām pusēm).

   Rādiusi ir koncentriski: iekšējais = ārējais − atstarpe.
     --r-3 (28) − --inset (8) = --r-2 (20);  --r-2 (20) − --inset (8) = --r-1 (12)
   Kontrasts uz balta: --text 19:1, --text-2 10:1, --text-3 6:1; balts teksts uz --accent 11:1.
   ========================================================================= */
@font-face{font-family:"Urbanist"; font-style:normal; font-weight:100 900; font-display:swap; src:url(index.php?font=latin) format("woff2");
  unicode-range:U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+02C6,U+02DA,U+02DC,U+0304,U+0308,U+0329,U+2000-206F,U+20AC,U+2122,U+2191,U+2193,U+2212,U+2215,U+FEFF,U+FFFD}
@font-face{font-family:"Urbanist"; font-style:normal; font-weight:100 900; font-display:swap; src:url(index.php?font=latin-ext) format("woff2");
  unicode-range:U+0100-02BA,U+02BD-02C5,U+02C7-02CC,U+02CE-02D7,U+02DD-02FF,U+0304,U+0308,U+0329,U+1D00-1DBF,U+1E00-1E9F,U+1EF2-1EFF,U+2020,U+20A0-20AB,U+20AD-20C0,U+2113,U+2C60-2C7F,U+A720-A7FF}

:root{
  /* krāsas */
  --bg:#f7f8fb;
  --panel:#ffffff;
  --surface:#ffffff;
  --surface-2:#eef1f6;
  --fog-1:#eef1f6;
  --fog-2:#a9b4c6;
  --fog:radial-gradient(130% 130% at 22% 28%, #eef1f6 0%, #e4e8f0 34%, #c6cedb 68%, #a9b4c6 100%);
  --border:#d8dde6;
  --text:#0b0b0e;            /* kraukļa melns */
  --text-2:#3a404b;
  --text-3:#5d6573;
  --placeholder:#8a92a0;
  --link:#0b0b0e;
  --hl:#0b0b0e;
  --accent:#55263d;          /* galaktikas violets — galvenās pogas */
  --accent-hover:#6b3250;
  --accent-ink:#ffffff;
  --danger:#c93a2e;
  --danger-ink:#ffffff;
  --danger-bg:#fdeceb;
  --danger-bd:#f1bcb6;
  --ok:#14653a;
  --ok-bg:#e7f5ec;
  --ok-bd:#b9dfc8;
  --star:#b7791f;
  --piste-green:#2f9e5b;
  --piste-blue:#2f7fd6;
  --piste-red:#d13f22;
  --shadow:0 1px 2px rgba(20,28,45,.05), 0 16px 36px -18px rgba(20,28,45,.18);

  /* tipogrāfija */
  --font:"Urbanist",ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif;
  --display:var(--font);
  --mono:ui-monospace,"SF Mono",Menlo,Consolas,monospace;
  --fs-xs:.8125rem; --fs-sm:.9375rem; --fs-md:1.0625rem; --fs-lg:1.1875rem;
  --fs-xl:1.4375rem; --fs-2xl:1.875rem; --fs-3xl:clamp(2.25rem,4.6vw,3.25rem);

  /* atstarpes: 4 px solis */
  --s1:4px; --s2:8px; --s3:12px; --s4:16px; --s5:24px; --s6:32px; --s7:48px; --s8:64px; --s9:96px;

  /* rādiusi */
  --r-1:12px; --r-2:20px; --r-3:28px; --inset-1:8px; --inset-2:8px; --r-pill:999px;

  /* saderība ar admin.php */
  --text-soft:var(--text-3); --text-faint:var(--placeholder); --radius:var(--r-1); --accent-strong:var(--accent);

  color-scheme:light;
}
*{box-sizing:border-box}
[hidden]{display:none!important}
html{-webkit-text-size-adjust:100%; scroll-behavior:smooth}
body{
  margin:0; min-height:100vh; min-height:100dvh; display:flex; flex-direction:column;
  font:500 var(--fs-md)/1.55 var(--font); color:var(--text); background:var(--bg);
  overflow-x:hidden; -webkit-font-smoothing:antialiased;
}

/* ---------- pamats ---------- */
main{flex:1}
.wrap{width:100%; max-width:1200px; margin:0 auto; padding-left:max(var(--s5),env(safe-area-inset-left,0px)); padding-right:max(var(--s5),env(safe-area-inset-right,0px))}
a{color:var(--link); text-underline-offset:3px; text-decoration-thickness:1px}
a:hover{text-decoration-thickness:2px}
:focus-visible{outline:2px solid var(--text); outline-offset:3px; border-radius:var(--r-1)}
.skip{position:absolute; left:-999px; top:var(--s2); z-index:20; background:var(--text); color:#fff; padding:var(--s2) var(--s4); border-radius:var(--r-pill); font-weight:700; text-decoration:none}
.skip:focus{left:var(--s3)}
h1,h2,h3{font-weight:700; text-wrap:balance; letter-spacing:-.025em; line-height:1.08; margin:0}
h1{font-size:var(--fs-3xl)}
h2{font-size:clamp(1.875rem,3.6vw,2.75rem)}
h3{font-size:var(--fs-xl); letter-spacing:-.015em}
p{margin:0}
p,li{max-width:66ch; text-wrap:pretty}
strong{font-weight:700}
.small{font-size:var(--fs-sm); color:var(--text-3)}
.code,code{font-family:var(--mono); font-size:.88em}
time,.num,table{font-variant-numeric:tabular-nums}
.icon{width:20px; height:20px; flex:none; stroke:currentColor; fill:none; stroke-width:2; stroke-linecap:round; stroke-linejoin:round}

/* trašu grūtības marķieri */
.piste{display:inline-block; width:12px; height:12px; border-radius:50%; flex:none; background:var(--piste-green)}
.piste-1{background:var(--piste-blue)}
.piste-2{background:var(--piste-red)}

/* ---------- galvene ---------- */
.bar{display:flex; align-items:center; justify-content:space-between; gap:var(--s2) var(--s5); flex-wrap:wrap; padding-block:var(--s4)}
.logo{display:flex; align-items:center; gap:var(--s3); font-weight:800; font-size:var(--fs-lg); letter-spacing:-.02em; color:var(--text); text-decoration:none; line-height:1}
.logo-dot{width:14px; height:14px; border-radius:50%; background:radial-gradient(circle at 35% 30%, #eef1f6, #a9b4c6 75%); box-shadow:0 0 0 1px rgba(20,28,45,.08)}
nav ul{display:flex; align-items:center; gap:var(--s1); list-style:none; margin:0; padding:0; flex-wrap:wrap}
nav a{display:block; padding:var(--s2) var(--s4); border-radius:var(--r-pill); color:var(--text-2); font-weight:600; font-size:var(--fs-sm); text-decoration:none; transition:color .15s, background-color .15s}
nav a:hover{color:var(--text); background:rgba(11,11,14,.05)}
.site-header nav a[aria-current="page"]{color:var(--text); background:var(--surface-2)}
.site-header nav a.nav-cta{margin-left:var(--s2); background:var(--text); color:#fff; font-weight:700}
.site-header nav a.nav-cta:hover{background:#2a2c33}

/* ---------- sākumlapa ---------- */
.hero{padding-top:var(--s2)}
.hero-card{position:relative; overflow:hidden; border-radius:var(--r-3); background:var(--fog); box-shadow:var(--shadow); padding:clamp(var(--s6),6vw,80px); min-height:min(64vh,580px); display:flex; flex-direction:column; justify-content:flex-end}
.hero-text{position:relative; z-index:1; max-width:700px}
.chip{display:inline-flex; align-items:center; gap:var(--s2); padding:var(--s2) var(--s4); border-radius:var(--r-pill); background:rgba(255,255,255,.72); font-size:var(--fs-sm); font-weight:700; color:var(--text); box-shadow:0 1px 2px rgba(20,28,45,.08)}
.hero h1{font-size:clamp(2.5rem,6.4vw,5rem); line-height:1; letter-spacing:-.035em; margin-top:var(--s5)}
.hero .lead{font-size:var(--fs-lg); color:var(--text-2); margin-top:var(--s5); max-width:50ch}
.hero-actions{display:flex; flex-wrap:wrap; align-items:center; gap:var(--s3) var(--s5); margin-top:var(--s6)}
.hero-actions .small{color:var(--text-2)}
/* slēpju sliedes sniegā */
.tracks{position:absolute; top:0; right:4%; height:100%; width:auto; aspect-ratio:6/7; pointer-events:none}
.tracks .spray{stroke:#fff; stroke-width:40; opacity:.34; fill:none; stroke-linecap:round}
.tracks .rail{stroke:#fff; stroke-width:3; fill:none; stroke-linecap:round; stroke-dasharray:1; animation:carve 2s cubic-bezier(.4,0,.2,1) both}
.tracks .rail + .rail{animation-delay:.1s}
@keyframes carve{from{stroke-dashoffset:1}to{stroke-dashoffset:0}}
.tracks .pole{stroke:var(--text); stroke-width:2.5; stroke-linecap:round}
.tracks .flag-red{fill:#d13f22}
.tracks .flag-blue{fill:#4c6a9c}

.facts{list-style:none; margin:0; padding:var(--s6) 0 0; display:grid; grid-template-columns:repeat(3,1fr); gap:var(--s5) var(--s6)}
.facts li{display:flex; gap:var(--s3); align-items:flex-start; color:var(--text-2); max-width:none; min-width:0}
.facts .piste{margin-top:.42em}

.section{padding-block:clamp(var(--s8),8vw,112px) 0}
.section:last-child{padding-bottom:clamp(var(--s8),8vw,112px)}
.section-head{display:grid; gap:var(--s3); margin-bottom:var(--s6)}
.section-head p{color:var(--text-2)}
.section-foot{margin-top:var(--s5)}

/* maiņas kā pacēlāja kartes */
.session-grid{display:grid; gap:var(--s4)}
.session{--stub:330px; display:grid; grid-template-columns:minmax(0,1fr) var(--stub); background:var(--surface); border-radius:var(--r-3); box-shadow:var(--shadow); min-width:0; overflow:hidden}
.session-body{padding:var(--s6); display:grid; gap:var(--s4); align-content:start; min-width:0}
.pass-top{display:flex; flex-wrap:wrap; align-items:baseline; gap:var(--s2) var(--s4)}
.pass-dates{font-weight:700; font-size:clamp(2.25rem,4.6vw,3.25rem); line-height:1; letter-spacing:-.035em; font-variant-numeric:tabular-nums}
.pass-dates .dash{color:var(--fog-2); padding-inline:.14em}
.pass-meta{font-size:var(--fs-sm); font-weight:700; color:var(--text-3)}
.session h3{font-size:var(--fs-lg); font-weight:700; letter-spacing:-.01em; color:var(--text-2)}
.seats{display:grid; gap:var(--s2); max-width:420px}
.meter{height:6px; border-radius:var(--r-pill); background:var(--surface-2); overflow:hidden}
.meter span{display:block; height:100%; border-radius:inherit; background:var(--text)}
.meter.full span{background:var(--fog-2)}
.seats p{font-size:var(--fs-sm); color:var(--text-2)}
.seats strong{color:var(--text)}
.incl-cols{display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:var(--s4) var(--s6)}
.incl{display:grid; gap:var(--s1); align-content:start; font-size:var(--fs-sm); color:var(--text-2)}
.incl h4{margin:0 0 var(--s1); font-size:var(--fs-sm); font-weight:700; color:var(--text)}
.incl ul{margin:0; padding-left:1.1rem}
.extras-list,.sum-lines{list-style:none; padding:0!important; margin:0; display:grid; gap:var(--s1)}
.extras-list li,.sum-lines li{display:flex; justify-content:space-between; gap:var(--s3)}
.sum-lines{max-width:22rem; margin-top:var(--s2); font-size:var(--fs-sm)}
/* nogrieznis: cena un pieteikšanās */
.session-cta{display:flex; flex-direction:column; gap:var(--s3); padding:var(--s6) var(--s5) var(--inset-2); background:var(--fog-1); border-left:2px dashed #c3cad6; min-width:0}
.session-cta .btn,.session-cta .sold-out{margin-top:auto; margin-inline:calc(var(--inset-2) - var(--s5)); border-radius:var(--r-2)}
.price{font-weight:700; font-size:clamp(2.25rem,4.4vw,3rem); line-height:1; letter-spacing:-.035em; font-variant-numeric:tabular-nums}
.price small{display:block; margin-top:var(--s2); font-size:var(--fs-sm); font-weight:600; letter-spacing:0; color:var(--text-3)}
.stub-extras{font-size:var(--fs-sm); color:var(--text-2); padding-top:var(--s3); border-top:1px solid #d3d9e3}
.sold-out{padding:var(--s4); text-align:center; font-weight:700; color:var(--text-3); background:rgba(11,11,14,.05)}

/* maiņas kā macOS piezīmes */
.notes{display:grid; grid-template-columns:repeat(auto-fill,minmax(min(100%,330px),1fr)); gap:var(--s5); align-items:start}
.note{
  --sys:-apple-system,BlinkMacSystemFont,"SF Pro Text","Helvetica Neue",Arial,sans-serif;
  display:flex; flex-direction:column; min-width:0; overflow:hidden; border-radius:12px; background:#fff;
  font-family:var(--sys); font-weight:400; color:#1d1d1f;
  box-shadow:0 0 0 .5px rgba(0,0,0,.22), 0 2px 6px rgba(0,0,0,.06), 0 24px 48px -18px rgba(20,28,45,.35);
  transition:box-shadow .2s;
}
.note.is-max{grid-column:1/-1}
.note.is-open{animation:note-open .28s cubic-bezier(.16,1,.3,1)}
@keyframes note-open{from{opacity:0; transform:scale(.96)}to{opacity:1; transform:none}}
.note-bar{position:relative; display:flex; align-items:center; min-height:38px; padding:0 var(--s3); background:linear-gradient(#f6f6f6,#e9e9eb); border-bottom:1px solid #d3d3d6}
.note-bar-title{position:absolute; left:84px; right:84px; text-align:center; font-size:13px; font-weight:600; color:#4d4d50; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; max-width:none}
.lights{display:flex; gap:8px; position:relative; z-index:1}
.light{width:12px; height:12px; padding:0; border-radius:50%; border:.5px solid rgba(0,0,0,.18); cursor:pointer; display:grid; place-items:center}
.light svg{width:8px; height:8px; stroke:rgba(0,0,0,.55); stroke-width:1.3; stroke-linecap:round; fill:none; opacity:0; transition:opacity .1s}
.lights:hover svg,.light:focus-visible svg{opacity:1}
.light:focus-visible{outline:2px solid #0a84ff; outline-offset:2px; border-radius:50%}
.light-close{background:#ff5f57; border-color:#e0443e}
.light-min{background:#febc2e; border-color:#dea123}
.light-max{background:#28c840; border-color:#1aab29}
.note-body{padding:var(--s5) var(--s5) var(--s4); display:grid; gap:var(--s2); align-content:start; font-size:15px; line-height:1.45}
.note-body p,.note-body li{max-width:none}
.note-date{text-align:center; font-size:12px; color:#8e8e93; margin-bottom:var(--s2)}
.note-title{font-family:var(--sys); font-size:26px; font-weight:700; letter-spacing:-.01em; line-height:1.15; color:#1d1d1f}
.note-price{font-size:15px}
.note-price .num{font-size:30px; font-weight:700; letter-spacing:-.02em; margin-right:var(--s1)}
.note-muted,.note-line{color:#6e6e73}
.note-line strong{color:#1d1d1f; font-weight:600}
.note .seats{margin-block:var(--s1) var(--s2)}
.note .seats p{color:#3a3a3c}
.note .meter{background:#ececf0}
.note .meter span{background:#55263d}
.note-h{font-weight:700; font-size:16px; margin-top:var(--s2)}
.note-check{list-style:none; margin:0; padding:0; display:grid; gap:6px}
.note-check li{position:relative; padding-left:28px; color:#3a3a3c}
.note-check li::before{content:""; position:absolute; left:0; top:1px; width:18px; height:18px; border-radius:50%; border:1.5px solid #c7c7cc; box-sizing:border-box}
.note-check li.done::before{border-color:#f2b705; background:#f2b705 url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16' fill='none' stroke='%23fff' stroke-width='2.4' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M4 8.5l2.6 2.5L12 5.5'/%3E%3C/svg%3E") center/12px no-repeat}
.note-extras li{display:flex; justify-content:space-between; gap:var(--s3)}
.note-foot{padding:0 var(--s3) var(--s3)}
.note-foot .btn{border-radius:8px}
.note-foot .sold-out{border-radius:8px}
.note.is-min .note-body,.note.is-min .note-foot{display:none}
.note.is-max .note-body{font-size:16px; padding:var(--s6) clamp(var(--s5),5vw,var(--s8)) var(--s5)}
.note.is-max .note-title{font-size:34px}
.note.is-max .note-extras{max-width:420px}
.note-restore{justify-self:start; font:inherit; font-size:var(--fs-sm); font-weight:700; color:var(--text); padding:var(--s3) var(--s4); border-radius:var(--r-pill); border:1px dashed #b8bfcb; background:transparent; cursor:pointer}
.note-restore:hover{background:var(--surface-2)}
/* rakstīšana */
.note .t-wait{visibility:hidden}
.note[data-typing] .note-check li::before,.note[data-typing] .meter{transition:none}
.caret{display:inline-block; width:2px; height:1.1em; margin-left:1px; vertical-align:-.15em; background:#f2b705; animation:blink .8s steps(1) infinite}
@keyframes blink{50%{opacity:0}}

/* pieteikšanās lapa kā macOS piezīme */
.note-page{max-width:860px; padding-block:var(--s6) var(--s9)}
.note-form{transition:max-width .25s}
.note-page:has(.note-form.is-max){max-width:1200px}
.note-form .light-close{text-decoration:none}
.note-form .note-body{padding:var(--s6) clamp(var(--s5),5vw,56px) var(--s7); gap:0; font-size:16px; line-height:1.5}
.note-form .note-body > * + *{margin-top:var(--s4)}
.note-form .note-date{margin-bottom:0}
.note-form .note-title{font-size:30px; margin-top:var(--s3)}
.note-form .note-body > p{color:#3a3a3c}
.note-form .stack{gap:var(--s5); margin-top:var(--s5)}
.note-form label,.note-form legend{font-family:var(--sys); font-size:15px; font-weight:600; color:#1d1d1f}
.note-form .hint{font-family:var(--sys); font-size:13px; font-weight:400; color:#8e8e93}
/* ievades lauki kā rindas piezīmē */
.note-form input[type=text],.note-form input[type=email],.note-form input[type=tel],.note-form input[type=number],.note-form select,.note-form textarea{
  font-family:var(--sys); font-size:16px; color:#1d1d1f; min-height:44px; padding:var(--s2) 2px;
  background-color:transparent; border:0; border-bottom:1px solid #d1d1d6; border-radius:0; box-shadow:none}
.note-form select{padding-right:32px; background-position:right 4px center}
.note-form textarea{min-height:96px; border:1px solid #d1d1d6; border-radius:8px; padding:var(--s3); line-height:1.5}
.note-form input:focus,.note-form select:focus{border-bottom-color:#f2b705; box-shadow:0 1px 0 #f2b705}
.note-form textarea:focus{border-color:#f2b705; box-shadow:0 0 0 3px rgba(242,183,5,.22)}
.note-form [aria-invalid="true"]{border-color:var(--danger)!important}
.note-form .check{font-family:var(--sys); font-size:15px; font-weight:400; color:#1d1d1f}
.note-form .check input{accent-color:#c99600}
.note-form .level,.note-form [data-extras] .check{border-color:#e5e5ea; border-radius:8px}
.note-form .level:has(input:checked),.note-form [data-extras] .check:has(input:checked){border-color:#f2b705; box-shadow:inset 0 0 0 1px #f2b705; background:#fffbea}
.note-form .total{background:#fffbea; border:1px solid #f5dc8a; border-radius:8px; font-family:var(--sys)}
.note-form .total strong{font-family:var(--sys); letter-spacing:-.02em}
.note-form .btn{font-family:var(--sys); border-radius:8px}
.note-form .notice,.note-form .errors{font-family:var(--sys); border-radius:8px}
.note-form .small{font-family:var(--sys); font-size:13px; color:#6e6e73}
.note-form .code-big{font-size:26px}
.note-form .stack > div:last-child .small{margin-top:var(--s2)}
@media (max-width:560px){ .note-page{padding-top:var(--s4)} .note-form .note-body{padding:var(--s5) var(--s4) var(--s6)} .note-form .note-title{font-size:26px} }

/* kā pieteikties */
.steps{list-style:none; margin:0; padding:0; display:grid; grid-template-columns:repeat(3,1fr); gap:var(--s6); counter-reset:step}
.steps li{display:grid; gap:var(--s2); align-content:start; max-width:none; min-width:0; padding-top:var(--s4); border-top:2px solid var(--text); counter-increment:step}
.steps li::before{content:counter(step); font-weight:700; font-size:var(--fs-sm); color:var(--text-3)}
.steps p{color:var(--text-2)}

/* ---------- satura lapas ---------- */
.panel-l{background:var(--panel); border-radius:var(--r-3); box-shadow:var(--shadow)}
.page.panel-l{background:none; border-radius:0; box-shadow:none}
.page{max-width:820px; padding-block:var(--s7) var(--s9)}
.page > * + *{margin-top:var(--s4)}
.page > h2{font-size:var(--fs-2xl); margin-top:var(--s7)}
.page > h1 + *{margin-top:var(--s5)}
.page p + p{margin-top:var(--s3)}
.page p,.page li{color:var(--text-2)}
.page ul,.page ol{padding-left:1.25rem}
.page li + li{margin-top:var(--s1)}

/* tabulas */
table{border-collapse:collapse; width:100%; margin:var(--s3) 0 0; font-size:var(--fs-sm)}
th,td{text-align:left; padding:var(--s3) var(--s4) var(--s3) 0; border-bottom:1px solid var(--border); vertical-align:top}
thead th{font-weight:700; color:var(--text)}
tbody th{color:var(--text-3); font-weight:600; width:38%}
.table-scroll{overflow-x:auto}
.table-scroll table{min-width:560px}

/* ---------- formas ---------- */
.stack{display:grid; gap:var(--s5)}
label{display:block; margin-bottom:var(--s2); font-size:var(--fs-sm); font-weight:700; color:var(--text)}
.hint{display:block; font-weight:500; font-size:var(--fs-sm); color:var(--text-3); margin-top:2px}
input[type=text],input[type=email],input[type=tel],input[type=number],input[type=password],input[type=date],select,textarea{
  width:100%; min-height:52px; padding:var(--s3) var(--s4); font:inherit; font-size:var(--fs-md);
  color:var(--text); background:#fff; border:1px solid #c9cfda; border-radius:var(--r-1);
  transition:border-color .15s, box-shadow .15s;
}
textarea{min-height:132px; resize:vertical}
select{appearance:none; background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%235d6573' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='m6 9 6 6 6-6'/%3E%3C/svg%3E"); background-repeat:no-repeat; background-position:right 14px center; background-size:18px; padding-right:44px}
input::placeholder,textarea::placeholder{color:var(--placeholder)}
input:focus,select:focus,textarea:focus{outline:none; border-color:var(--text); box-shadow:0 0 0 3px rgba(11,11,14,.12)}
[aria-invalid="true"]{border-color:var(--danger)!important; animation:nudge .32s ease-out 1}
@keyframes nudge{0%,100%{transform:none}25%{transform:translateX(-4px)}75%{transform:translateX(4px)}}
fieldset{border:0; padding:0; margin:0; min-width:0}
legend{font-size:var(--fs-sm); font-weight:700; color:var(--text); padding:0; margin-bottom:var(--s1)}
.check{display:flex; gap:var(--s3); align-items:flex-start; font-size:var(--fs-md); font-weight:500; color:var(--text); margin:var(--s2) 0 0}
.check input{width:20px; height:20px; margin:3px 0 0; flex:none; accent-color:var(--text)}
/* izvēles kartītes (līmenis, papildu pakalpojumi) */
.levels{display:grid; grid-template-columns:repeat(auto-fit,minmax(210px,1fr)); gap:var(--s2); margin-top:var(--s3)}
.level,[data-extras] .check{align-items:center; margin:var(--s3) 0 0; padding:var(--s4); border:1px solid #c9cfda; border-radius:var(--r-1); background:#fff; cursor:pointer; transition:border-color .15s, box-shadow .15s}
.levels .level{margin:0}
.level input,[data-extras] .check input{margin:0}
.level:hover,[data-extras] .check:hover{border-color:#9aa3b2}
.level:has(input:checked),[data-extras] .check:has(input:checked){border-color:var(--text); box-shadow:inset 0 0 0 1px var(--text)}
[data-extras] .check > span{display:flex; justify-content:space-between; gap:var(--s3); flex:1}
.stars-input{display:flex; gap:var(--s5); flex-wrap:wrap}
.hp{position:absolute; left:-9999px; width:1px; height:1px; overflow:hidden}
.error{display:block; margin-top:var(--s2); color:#a3261d; font-size:var(--fs-sm); font-weight:700}
.total{max-width:none; display:flex; flex-wrap:wrap; align-items:baseline; gap:var(--s2) var(--s3); padding:var(--s5); border-radius:var(--r-2); background:var(--fog); font-size:var(--fs-lg); font-weight:600; color:var(--text)}
.total strong{font-size:clamp(2rem,4.6vw,2.75rem); line-height:1; letter-spacing:-.035em; margin-left:auto}
.total .small{color:var(--text-2)}

/* ---------- pogas ---------- */
.btn{
  --px:var(--s5);
  position:relative; display:inline-flex; align-items:center; justify-content:center; gap:var(--s2);
  min-height:48px; padding:var(--s2) var(--px); font:inherit; font-weight:700; font-size:var(--fs-md); line-height:1.2;
  color:var(--text); text-align:center; text-decoration:none; cursor:pointer;
  background:#fff; border:1px solid #c9cfda; border-radius:var(--r-pill);
  transition:transform .08s, background-color .15s, border-color .15s, color .15s;
}
.btn:hover{background:var(--surface-2); border-color:#9aa3b2}
.btn:active{transform:scale(.98)}
.btn .icon{width:18px; height:18px; transition:transform .15s}
.btn:hover > .icon:last-child{transform:translateX(3px)}
.btn:has(> .icon:last-child){padding-right:calc(var(--px) - 4px)}
.btn-primary{background:var(--accent); border-color:var(--accent); color:var(--accent-ink)}
.btn-primary:hover{background:var(--accent-hover); border-color:var(--accent-hover)}
.btn-lg{min-height:56px; font-size:var(--fs-lg); --px:var(--s6)}
.btn-block{display:flex; width:100%}
.btn-danger{background:#fff; border-color:var(--danger); color:#a3261d}
.btn-danger:hover{background:var(--danger-bg); border-color:var(--danger)}
.linklike{background:none; border:0; padding:0; font:inherit; color:var(--link); text-decoration:underline; text-underline-offset:3px; cursor:pointer}
.textlink{font-weight:700}
.btn.is-busy{pointer-events:none; cursor:progress}
.spinner{width:16px; height:16px; flex:none; border:2px solid currentColor; border-right-color:transparent; border-radius:50%; animation:spin .7s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}

/* ---------- paziņojumi ---------- */
.notice{padding:var(--s4) var(--s5); border-radius:var(--r-2); background:var(--ok-bg); border:1px solid var(--ok-bd); color:var(--text-2); animation:enter .28s cubic-bezier(.16,1,.3,1)}
.notice strong{color:var(--text)}
.notice p + p{margin-top:var(--s2)}
.errors{padding:var(--s4) var(--s5); border-radius:var(--r-2); background:var(--danger-bg); border:1px solid var(--danger-bd); color:#8f1f17; animation:enter .28s cubic-bezier(.16,1,.3,1)}
.errors:focus{outline:none; box-shadow:0 0 0 3px rgba(201,58,46,.25)}
.errors ul{margin:var(--s1) 0 0; padding-left:1.1rem}
.errors a{color:#8f1f17}
@keyframes enter{from{opacity:0; transform:translateY(-6px)}to{opacity:1; transform:none}}
.code-row{display:flex; flex-wrap:wrap; align-items:center; gap:var(--s3)}
.code-big{font-family:var(--mono); font-size:var(--fs-2xl); font-weight:700; letter-spacing:.08em; color:var(--text)}
.copied .icon-copy,.icon-check{display:none}
.copied .icon-check{display:block; animation:pop .25s ease-out}
@keyframes pop{from{transform:scale(.4)}to{transform:scale(1)}}

/* ---------- atsauksmes ---------- */
.rating-summary{display:flex; align-items:baseline; gap:var(--s3); margin-top:var(--s5)}
.rating-summary .num{font-size:3rem; font-weight:700; line-height:1; letter-spacing:-.035em}
.review{border-top:1px solid var(--border); padding:var(--s4) 0}
.review p + p{margin-top:var(--s2)}
.stars{color:var(--star); letter-spacing:2px; line-height:1}

/* ---------- kājene ---------- */
.site-footer{border-top:1px solid var(--border); padding-block:var(--s7); font-size:var(--fs-sm); color:var(--text-3)}
.foot{display:flex; justify-content:space-between; gap:var(--s5); flex-wrap:wrap}
.foot p + p{margin-top:var(--s2)}
.foot strong{color:var(--text)}
.foot-links{list-style:none; padding:0; margin:0; display:grid; grid-template-columns:repeat(2,auto); gap:var(--s2) var(--s6); align-content:start}
.foot-links a,.foot-links .linklike{color:var(--text-2)}

/* ---------- kļūdas ziņojuma poga ---------- */
.bug-fab{position:fixed; z-index:20; left:calc(var(--s4) + env(safe-area-inset-left,0px)); bottom:calc(var(--s4) + env(safe-area-inset-bottom,0px));
  display:inline-flex; align-items:center; gap:var(--s2); padding:var(--s2) var(--s4) var(--s2) var(--s3); border-radius:var(--r-pill);
  background:#fff; color:var(--text); font-size:var(--fs-sm); font-weight:700; text-decoration:none;
  box-shadow:0 0 0 1px rgba(20,28,45,.1), 0 8px 24px -10px rgba(20,28,45,.35); transition:transform .15s, box-shadow .15s}
.bug-fab:hover{transform:translateY(-2px); box-shadow:0 0 0 1px rgba(20,28,45,.16), 0 12px 28px -10px rgba(20,28,45,.4)}
.bug-fab .icon{width:18px; height:18px}
body:has(#consent:not([hidden])) .bug-fab{display:none}   /* nepārklājas ar sīkdatņu logu */
@media (max-width:560px){ .bug-fab span{position:absolute; width:1px; height:1px; overflow:hidden; clip:rect(0 0 0 0)} .bug-fab{padding:var(--s3)} }

/* ---------- sīkdatņu logs ---------- */
.consent{
  position:fixed; z-index:30; max-width:440px;
  right:calc(var(--s4) + env(safe-area-inset-right,0px)); bottom:calc(var(--s4) + env(safe-area-inset-bottom,0px)); left:calc(var(--s4) + env(safe-area-inset-left,0px)); margin-left:auto;
  background:#fff; border-radius:var(--r-2); box-shadow:0 2px 6px rgba(20,28,45,.08), 0 24px 56px -16px rgba(20,28,45,.35);
  color:var(--text-2); font-size:var(--fs-sm); animation:rise-in .3s cubic-bezier(.16,1,.3,1);
}
@keyframes rise-in{from{opacity:0; transform:translateY(12px)}to{opacity:1; transform:none}}
.consent-body{padding:var(--s5) var(--s5) var(--s3)}
.consent h2{font-size:var(--fs-xl); color:var(--text); margin-bottom:var(--s2)}
.consent .check{font-size:var(--fs-sm)}
.consent .row{display:grid; grid-template-columns:repeat(3,1fr); gap:var(--inset-1); padding:var(--inset-1)}
.consent .row .btn{--px:var(--s2); font-size:var(--fs-sm); min-height:44px; border-radius:var(--r-1)}

@media (max-width:900px){
  .tracks{right:-18%; opacity:.7}
  .facts,.steps{grid-template-columns:1fr}
  .facts{gap:var(--s3)}
  .steps{gap:var(--s5)}
  .session{grid-template-columns:1fr}
  .session-body{padding:var(--s5)}
  .session-cta{border-left:0; border-top:2px dashed #c3cad6; padding:var(--s5) var(--s5) var(--inset-2)}
}
@media (max-width:560px){
  .wrap{padding-left:max(var(--s4),env(safe-area-inset-left,0px)); padding-right:max(var(--s4),env(safe-area-inset-right,0px))}
  .site-header nav a.nav-cta{margin-left:0}
  .hero-card{min-height:0; padding:var(--s7) var(--s5) var(--s5)}
  .tracks{right:-40%; opacity:.55}
  .tracks > g:not(.skier-wrap){display:none}
  .foot-links{grid-template-columns:1fr}
  tbody th{width:auto}
  .consent .row{grid-template-columns:1fr}
  .total strong{margin-left:0}
}
@media (prefers-reduced-motion: reduce){
  *,*::before,*::after{animation:none!important; transition:none!important}
  html{scroll-behavior:auto}
  .spinner{animation:spin 1.6s linear infinite!important}
}
CSS;
}

function site_js(): string
{
    return <<<'JS'

/* sīkdatņu paziņojums: "Noraidīt" un "Pieņemt" vienlīdz redzami, nekas nav iepriekš atzīmēts */
(function () {
  var box = document.getElementById('consent'); if (!box) return;
  var stat = document.getElementById('c-stat'), last = null;
  function get() { var m = document.cookie.match(/(?:^|; )cookie_consent=([^;]*)/); return m ? decodeURIComponent(m[1]) : null; }
  function loadOptional() { /* Šeit ielādēt statistikas rīkus TIKAI pēc piekrišanas. Pašlaik nav neviena. */ }
  function set(v) {
    document.cookie = 'cookie_consent=' + v + '; Max-Age=' + (60 * 60 * 24 * 182) + '; Path=/; SameSite=Lax' + (location.protocol === 'https:' ? '; Secure' : '');
    box.hidden = true; if (v === 'all') loadOptional(); if (last && last.focus) last.focus();
  }
  function open() { last = document.activeElement; stat.checked = get() === 'all'; box.hidden = false; box.querySelector('button').focus(); }
  var cur = get(); if (!cur) box.hidden = false; else if (cur === 'all') loadOptional();
  document.addEventListener('click', function (e) {
    if (!e.target.closest) return;
    if (e.target.closest('[data-open-consent]')) { e.preventDefault(); open(); return; }
    var c = e.target.closest('[data-consent]'); if (!c) return;
    var v = c.getAttribute('data-consent'); set(v === 'save' ? (stat.checked ? 'all' : 'necessary') : v);
  });
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape' && !box.hidden) box.hidden = true; });
})();
/* fokuss uz kļūdām, apstiprinājums, ielādes stāvoklis pogām, koda kopēšana */
(function () {
  var k = document.getElementById('kludas'); if (k) k.focus();

  document.addEventListener('submit', function (e) {
    var f = e.target;
    if (f.getAttribute('data-busy') === '1') { e.preventDefault(); return; }   // novērš dubultu iesniegšanu
    var m = f.getAttribute('data-confirm');
    if (m && !window.confirm(m)) { e.preventDefault(); return; }
    var b = e.submitter || f.querySelector('button[type=submit]');
    f.setAttribute('data-busy', '1');
    if (!b || b.tagName !== 'BUTTON') return;
    b.style.minWidth = b.offsetWidth + 'px';
    b.setAttribute('data-label', b.innerHTML);
    b.classList.add('is-busy'); b.setAttribute('aria-busy', 'true');
    // poga netiek atspējota (disabled), lai tās name/value nonāk līdz serverim
    var t = b.getAttribute('data-busy-text') || 'Saglabā…';
    setTimeout(function () { b.innerHTML = '<span class="spinner" aria-hidden="true"></span><span>' + t + '</span>'; }, 0);
  });
  // atgriežoties ar pogu "Atpakaļ", pogas atjauno sākotnējo stāvokli
  window.addEventListener('pageshow', function () {
    document.querySelectorAll('form[data-busy]').forEach(function (f) { f.removeAttribute('data-busy'); });
    document.querySelectorAll('.is-busy').forEach(function (b) {
      b.classList.remove('is-busy'); b.removeAttribute('aria-busy'); b.style.minWidth = '';
      if (b.getAttribute('data-label')) b.innerHTML = b.getAttribute('data-label');
    });
  });

  document.addEventListener('click', function (e) {
    var b = e.target.closest && e.target.closest('[data-copy]'); if (!b) return;
    var el = document.querySelector(b.getAttribute('data-copy')); if (!el) return;
    var text = el.textContent.trim(), label = b.querySelector('span');
    function done() {
      b.classList.add('copied'); if (label) label.textContent = b.getAttribute('data-copied-text') || 'Nokopēts';
      clearTimeout(b._t); b._t = setTimeout(function () { b.classList.remove('copied'); if (label) label.textContent = 'Kopēt'; }, 2000);
    }
    function fallback() { var r = document.createRange(); r.selectNodeContents(el); var s = getSelection(); s.removeAllRanges(); s.addRange(r); }
    if (navigator.clipboard) navigator.clipboard.writeText(text).then(done, fallback); else fallback();
  });
})();
/* ēdināšanas norādes: piekrišanas rūtiņa parādās, tiklīdz kaut kas ir ierakstīts */
(function () {
  var t = document.querySelector('[data-food-notes]'), c = document.querySelector('[data-food-consent]'); if (!t || !c) return;
  function upd() { if (t.value.trim() !== '') c.hidden = false; }
  t.addEventListener('input', upd); upd();
})();
/* slēpotājs sākumlapā: pirmo reizi drīz pēc ielādes, tad reizi minūtē (index.php#slepotajs — uzreiz, pārbaudei) */
(function () {
  var run = document.getElementById('skier-run'), skier = document.getElementById('skier'); if (!run || !skier || !run.beginElement) return;
  if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  var timer = null;
  function go() {
    if (document.hidden) return;
    skier.style.visibility = 'visible'; run.beginElement();
    clearTimeout(timer); timer = setTimeout(function () { skier.style.visibility = 'hidden'; }, 6100);
  }
  setTimeout(go, location.hash === '#slepotajs' ? 600 : 2800);
  setInterval(go, 60000);
})();
/* maiņu piezīmes: luksofora pogas un "rakstīšana" pirms pieteikuma formas */
(function () {
  var reduced = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  document.addEventListener('click', function (e) {
    if (!e.target.closest) return;
    var act = e.target.closest('[data-note-act]');
    if (act) {
      var note = act.closest('[data-note]'), kind = act.getAttribute('data-note-act');
      if (kind === 'close') {
        var r = note.nextElementSibling; note.hidden = true;
        if (r && r.hasAttribute('data-note-restore')) { r.hidden = false; r.focus(); }
      } else if (kind === 'min') {
        var min = note.classList.toggle('is-min'); act.setAttribute('aria-expanded', min ? 'false' : 'true');
      } else {
        var max = note.classList.toggle('is-max'); act.setAttribute('aria-pressed', max ? 'true' : 'false');
        note.classList.remove('is-min'); note.querySelector('.light-min').setAttribute('aria-expanded', 'true');
        if (max && note.scrollIntoView) note.scrollIntoView({ block: 'nearest', behavior: reduced ? 'auto' : 'smooth' });
      }
      return;
    }
    var restore = e.target.closest('[data-note-restore]');
    if (restore) {
      var n = restore.previousElementSibling; restore.hidden = true;
      if (n) { n.hidden = false; n.classList.add('is-open'); var b = n.querySelector('.light-close'); if (b) b.focus(); }
      return;
    }
    var go = e.target.closest('[data-note-go]');
    if (!go || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button !== 0 || reduced) return;
    var card = go.closest('[data-note]'); e.preventDefault();
    if (card.hasAttribute('data-typing')) return;
    card.setAttribute('data-typing', '1'); card.classList.remove('is-min');
    go.style.minWidth = go.offsetWidth + 'px'; go.classList.add('is-busy'); go.setAttribute('aria-busy', 'true');
    go.innerHTML = '<span class="spinner" aria-hidden="true"></span><span>Atver pieteikumu…</span>';
    // notīra piezīmi un ieraksta to pašu tekstu no jauna, ātri
    var body = card.querySelector('.note-body'), items = [], total = 0;
    var walker = document.createTreeWalker(body, NodeFilter.SHOW_TEXT, null), t;
    while ((t = walker.nextNode())) {
      if (!t.nodeValue.trim()) continue;
      var block = t.parentNode.closest('p,li,h3,.seats') || t.parentNode;
      items.push({ node: t, text: t.nodeValue, block: block }); total += t.nodeValue.length; t.nodeValue = '';
      block.classList.add('t-wait');
    }
    var caret = document.createElement('span'); caret.className = 'caret'; caret.setAttribute('aria-hidden', 'true');
    var dur = Math.min(1100, Math.max(450, total * 3)), start = null, done = 0, idx = 0;
    function step(now) {
      if (start === null) start = now;
      var target = Math.min(total, Math.ceil(total * (now - start) / dur));
      while (done < target && idx < items.length) {
        var it = items[idx], room = it.text.length - it.node.nodeValue.length, take = Math.min(room, target - done);
        it.block.classList.remove('t-wait');
        it.node.nodeValue = it.text.slice(0, it.node.nodeValue.length + take); done += take;
        it.node.parentNode.insertBefore(caret, it.node.nextSibling);
        if (it.node.nodeValue.length === it.text.length) idx++;
      }
      if (done < total) { requestAnimationFrame(step); return; }
      setTimeout(function () { caret.remove(); location.href = go.href; }, 260);
    }
    requestAnimationFrame(step);
  });
  window.addEventListener('pageshow', function (e) { if (e.persisted && document.querySelector('[data-note][data-typing]')) location.reload(); });
})();
/* pieteikuma forma: cena pēc vecuma, papildu pakalpojumi un kopsumma mainās līdz ar izvēli (galīgo summu rēķina serveris) */
(function () {
  var sel = document.getElementById('f-session_id'), totalRow = document.querySelector('[data-total-row]'); if (!sel || !totalRow) return;
  var box = document.querySelector('[data-extras]'), totalEl = totalRow.querySelector('[data-total]');
  var ageEl = document.getElementById('f-participant_age'), ageNote = document.querySelector('[data-age-note]');
  function eur(c) { return (c / 100).toFixed(2).replace('.', ',').replace(/\B(?=(\d{3})+(?!\d))/g, ' ') + ' €'; }
  function update() {
    var o = sel.options[sel.selectedIndex], has = o && o.value !== '', any = false;
    var p16 = has ? +o.getAttribute('data-price16') : 0, adult = p16 > 0 && parseInt(ageEl.value, 10) >= 16;
    var sum = has ? (adult ? p16 : +o.getAttribute('data-price')) : 0;
    if (ageNote) { ageNote.hidden = !adult; if (adult) ageNote.querySelector('[data-age-price]').textContent = eur(p16); }
    if (box) {
      ['rental', 'hotel'].forEach(function (k) {
        var row = box.querySelector('[data-extra="' + k + '"]'), cb = row.querySelector('input'), c = has ? +o.getAttribute('data-' + k) : 0;
        row.hidden = !c; if (!c) cb.checked = false; else any = true;
        row.querySelector('[data-extra-price]').textContent = c ? '+' + eur(c) : '';
        if (k === 'hotel' && c) row.querySelector('[data-hotel-label]').textContent = o.getAttribute('data-hotel-label');
        if (cb.checked) sum += c;
      });
      box.hidden = !any;
    }
    totalRow.hidden = !has; if (has) totalEl.textContent = eur(sum);
  }
  sel.addEventListener('change', update); ageEl.addEventListener('input', update);
  if (box) box.addEventListener('change', update);
  update();
})();
JS;
}

if (defined('NOMETNE_CORE_ONLY')) return;   // admin.php izmanto tikai augšējās funkcijas

/* ============================== LAPAS ===================================== */

function page_start(string $title, string $active = ''): void
{
    $nav = ['sakums' => 'Sākums', 'pieteikties' => 'Pieteikties', 'atsauksmes' => 'Atsauksmes', 'kontakti' => 'Kontakti'];
    $flash = flash();
    ?><!doctype html>
<html lang="lv">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light">
<meta name="theme-color" content="#f7f8fb">
<title><?= e($title) ?> · Slēpošanas nometne</title>
<style><?= site_css() ?></style>
</head>
<body>
<a class="skip" href="#saturs">Pāriet uz saturu</a>
<header class="site-header">
  <div class="wrap bar">
    <a class="logo" href="<?= url() ?>"><span class="logo-dot" aria-hidden="true"></span>Slēpošanas nometne</a>
    <nav aria-label="Galvenā navigācija"><ul>
      <?php foreach ($nav as $p => $label): if ($p === 'pieteikties') continue; ?>
        <li><a href="<?= url($p) ?>"<?= $active === $p ? ' aria-current="page"' : '' ?>><?= e($label) ?></a></li>
      <?php endforeach; ?>
      <li><a class="nav-cta" href="<?= url('pieteikties') ?>"<?= $active === 'pieteikties' ? ' aria-current="page"' : '' ?>>Pieteikties</a></li>
    </ul></nav>
  </div>
</header>
<main id="saturs">
<?php if ($flash): ?><div class="wrap" style="padding-top:var(--s5)"><p class="notice" role="status"><?= e($flash) ?></p></div><?php endif;
}

function page_end(): void
{
    ?>
</main>
<?php $here = (string)($_GET['p'] ?? 'sakums'); if ($here !== 'zinot-kludu'): ?>
<a class="bug-fab" href="<?= url('zinot-kludu', ['no' => $here]) ?>"><svg class="icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="M8 7V5a4 4 0 0 1 8 0v2"/><rect x="6" y="7" width="12" height="13" rx="6"/><path d="M12 11v9M3 12h3M18 12h3M4 18l2.5-1.5M20 18l-2.5-1.5M4 6l2.5 1.5M20 6l-2.5 1.5"/></svg><span>Ziņot par kļūdu</span></a>
<?php endif; ?>
<footer class="site-footer">
  <div class="wrap foot">
    <div>
      <p><strong><?= e(cfg('company_name')) ?></strong></p>
      <p>Reģ. nr. <?= e(cfg('reg_number')) ?> · PVN <?= e(cfg('vat_number')) ?><br><?= e(cfg('legal_address')) ?></p>
      <p><a href="mailto:<?= e(cfg('email')) ?>"><?= e(cfg('email')) ?></a> · <?= e(cfg('phone')) ?></p>
    </div>
    <ul class="foot-links">
      <li><a href="<?= url('privatums') ?>">Privātuma politika</a></li>
      <li><a href="<?= url('noteikumi') ?>">Lietošanas noteikumi</a></li>
      <li><a href="<?= url('atmaksa') ?>">Atmaksas politika</a></li>
      <li><a href="<?= url('sikdatnes') ?>">Sīkdatņu politika</a></li>
      <li><a href="<?= url('mani-dati') ?>">Mani dati</a></li>
      <li><a href="<?= url('zinot-kludu', ['no' => (string)($_GET['p'] ?? 'sakums')]) ?>">Ziņot par kļūdu</a></li>
      <li><button type="button" class="linklike" data-open-consent>Sīkdatņu iestatījumi</button></li>
    </ul>
  </div>
</footer>
<div class="consent" role="dialog" aria-labelledby="c-h" aria-describedby="c-d" hidden id="consent">
  <div class="consent-body">
    <h2 id="c-h">Sīkdatnes</h2>
    <p id="c-d">Izmantojam tikai nepieciešamās sīkdatnes. Statistikas sīkdatnes pašlaik netiek izmantotas. <a href="<?= url('sikdatnes') ?>">Uzzināt vairāk</a></p>
    <label class="check"><input type="checkbox" disabled checked> <span>Nepieciešamās (vienmēr)</span></label>
    <label class="check"><input type="checkbox" id="c-stat"> <span>Statistika</span></label>
  </div>
  <div class="row">
    <button class="btn" type="button" data-consent="necessary">Noraidīt</button>
    <button class="btn" type="button" data-consent="save">Saglabāt izvēli</button>
    <button class="btn" type="button" data-consent="all">Pieņemt visas</button>
  </div>
</div>
<script nonce="<?= csp_nonce() ?>"><?= site_js() ?></script>
</body>
</html>
<?php
}

/* ---------- Sākums ---------- */
function page_sakums(): void
{
    $sessions = db()->query('SELECT * FROM mk_camp_sessions WHERE active = 1 ORDER BY start_date')->fetchAll();
    page_start('Sākums', 'sakums');
    $sy1 = $sessions ? date('Y', strtotime($sessions[0]['start_date'])) : date('Y');
    $sy2 = $sessions ? date('Y', strtotime(end($sessions)['end_date'])) : $sy1;
    $season = $sy1 === $sy2 ? $sy1 : $sy1 . '/' . substr($sy2, 2);
    $rail = 'M430 -20 C240 70 230 170 380 260 S560 410 400 500 S200 610 340 730';
    ?>
<section class="hero">
  <div class="wrap">
    <div class="hero-card">
      <svg class="tracks" viewBox="0 0 600 700" aria-hidden="true" focusable="false">
        <path class="spray" d="<?= $rail ?>" transform="translate(8 0)"/>
        <path class="rail" pathLength="1" d="<?= $rail ?>"/>
        <path class="rail" pathLength="1" d="<?= $rail ?>" transform="translate(16 0)"/>
        <?php foreach ([[232, 92, 'red'], [498, 372, 'blue'], [232, 584, 'red']] as [$gx, $gy, $gc]): ?>
        <g transform="translate(<?= $gx ?> <?= $gy ?>)">
          <line class="pole" x1="0" y1="0" x2="0" y2="46"/><line class="pole" x1="32" y1="0" x2="32" y2="46"/>
          <rect class="flag-<?= $gc ?>" x="0" y="2" width="32" height="20" rx="2"/>
        </g>
        <?php endforeach; ?>
        <!-- slēpotājs: reizi minūtē nobrauc pa trasi (palaiž skripts; ja kustība samazināta — nebrauc) -->
        <g class="skier-wrap" transform="translate(8 0)">
          <g id="skier" style="visibility:hidden">
            <animateMotion id="skier-run" dur="6s" begin="indefinite" fill="freeze" calcMode="spline" keyTimes="0;1" keySplines=".3 0 .6 1" path="<?= $rail ?>"/>
            <g transform="scale(1.8)">
              <line x1="-16" y1="15" x2="16" y2="15" stroke="#0b0b0e" stroke-width="2.6" stroke-linecap="round"/>
              <path d="M-5 14 L-2 4 M5 14 L2 4" stroke="#0b0b0e" stroke-width="3.4" stroke-linecap="round" fill="none"/>
              <path d="M-4 5 L4 5 L6 -9 L-2 -10 Z" fill="#55263d"/>
              <circle cx="3" cy="-14" r="4.4" fill="#d13f22"/>
              <line x1="6" y1="-4" x2="-11" y2="15" stroke="#5d6573" stroke-width="1.4" stroke-linecap="round"/>
            </g>
          </g>
        </g>
      </svg>
      <div class="hero-text">
        <p class="chip">Ziemas sezona <?= e($season) ?></p>
        <h1>Slēpošanas dienas nometne bērniem no&nbsp;7 līdz 16&nbsp;gadiem</h1>
        <p class="lead">Mācāmies grupās pēc prasmju līmeņa — no pirmajiem soļiem uz slēpēm līdz carving tehnikai.</p>
        <div class="hero-actions">
          <a class="btn btn-primary btn-lg" href="#mainas">Izvēlēties maiņu <?= icon('arrow') ?></a>
          <?php if ($sessions): $first = $sessions[0]; ?>
            <p class="small">Nākamā maiņa sākas <time datetime="<?= e($first['start_date']) ?>"><?= e(dmy($first['start_date'])) ?></time></p>
          <?php endif; ?>
        </div>
      </div>
    </div>
    <ul class="facts">
      <li><span class="piste piste-0" aria-hidden="true"></span><span>Līdz 8 bērniem uz vienu instruktoru</span></li>
      <li><span class="piste piste-1" aria-hidden="true"></span><span>Instruktori ar <?= e(cfg('instructor_cert')) ?> sertifikātu</span></li>
      <li><span class="piste piste-2" aria-hidden="true"></span><span>9:00–16:00: divas nodarbības uz trases, pusdienas un atpūta siltās telpās</span></li>
    </ul>
  </div>
</section>

<section class="section sessions" id="mainas" aria-labelledby="h-mainas">
  <div class="wrap">
    <div class="section-head">
      <h2 id="h-mainas">Maiņas un cenas</h2>
      <p>Cenas ir ar PVN. Papildu pakalpojumus izvēlaties pats pieteikumā — nekas netiek pievienots automātiski, un citu maksu nav.</p>
    </div>
    <?php if (!$sessions): ?>
      <p>Šobrīd nav atvērtu maiņu. Rakstiet mums: <a href="mailto:<?= e(cfg('email')) ?>"><?= e(cfg('email')) ?></a>.</p>
    <?php else: ?>
    <div class="notes">
      <?php foreach ($sessions as $s):
        $sid = (int)$s['id'];
        $cap = max(1, (int)$s['capacity']);
        $taken = min($cap, seats_taken($sid));
        $left = $cap - $taken;
        $inc = lines($s['includes']); $exc = lines($s['excludes']); ?>
      <article class="note" data-note aria-labelledby="note-t-<?= $sid ?>">
        <div class="note-bar">
          <div class="lights">
            <button type="button" class="light light-close" data-note-act="close" aria-label="Aizvērt piezīmi"><svg viewBox="0 0 8 8" aria-hidden="true"><path d="M2 2l4 4M6 2L2 6"/></svg></button>
            <button type="button" class="light light-min" data-note-act="min" aria-label="Minimizēt piezīmi" aria-expanded="true"><svg viewBox="0 0 8 8" aria-hidden="true"><path d="M1.5 4h5"/></svg></button>
            <button type="button" class="light light-max" data-note-act="max" aria-label="Maksimizēt piezīmi" aria-pressed="false"><svg viewBox="0 0 8 8" aria-hidden="true"><path d="M4 1.5v5M1.5 4h5"/></svg></button>
          </div>
          <p class="note-bar-title" aria-hidden="true"><?= e($s['title']) ?></p>
        </div>
        <div class="note-body">
          <p class="note-date"><time datetime="<?= e($s['start_date']) ?>"><?= e(dmy($s['start_date'])) ?></time> – <time datetime="<?= e($s['end_date']) ?>"><?= e(dmy($s['end_date'])) ?></time> · <?= e(plural_days(session_days($s))) ?></p>
          <h3 class="note-title" id="note-t-<?= $sid ?>"><?= e($s['title']) ?></h3>
          <p class="note-price"><span class="num"><?= e(money((int)$s['price_cents'])) ?></span> <span class="note-muted">ar PVN</span></p>
          <?php if ((int)$s['price16_cents'] > 0 && (int)$s['price16_cents'] !== (int)$s['price_cents']): ?>
            <p class="note-line">Līdz 15 gadiem. No 16 gadiem: <strong class="num"><?= e(money((int)$s['price16_cents'])) ?></strong></p>
          <?php endif; ?>
          <div class="seats">
            <div class="meter<?= $left ? '' : ' full' ?>" aria-hidden="true"><span style="width:<?= round($taken / $cap * 100) ?>%"></span></div>
            <p><?php if ($left): ?>Brīvas <strong class="num"><?= $left ?></strong> no <span class="num"><?= $cap ?></span> vietām<?php else: ?>Visas <span class="num"><?= $cap ?></span> vietas aizņemtas<?php endif; ?></p>
          </div>
          <?php if ($inc): ?>
            <p class="note-h">Cenā iekļauts</p>
            <ul class="note-check"><?php foreach ($inc as $line): ?><li class="done"><?= e($line) ?></li><?php endforeach; ?></ul>
          <?php endif; ?>
          <?php if ($exc): ?>
            <p class="note-h">Nav iekļauts</p>
            <ul class="note-check"><?php foreach ($exc as $line): ?><li><?= e($line) ?></li><?php endforeach; ?></ul>
          <?php endif; ?>
          <?php if ((int)$s['rental_cents'] > 0 || (int)$s['hotel_cents'] > 0): ?>
            <p class="note-h">Pēc izvēles</p>
            <ul class="note-check note-extras">
              <?php if ((int)$s['rental_cents'] > 0): ?><li><span>Inventāra noma</span> <span class="num">+<?= e(money((int)$s['rental_cents'])) ?></span></li><?php endif; ?>
              <?php if ((int)$s['hotel_cents'] > 0): ?><li><span><?= e(hotel_label($s)) ?></span> <span class="num">+<?= e(money((int)$s['hotel_cents'])) ?></span></li><?php endif; ?>
            </ul>
          <?php endif; ?>
        </div>
        <div class="note-foot">
          <?php if ($left > 0): ?>
            <a class="btn btn-primary btn-block" data-note-go href="<?= url('pieteikties', ['session' => $sid]) ?>" aria-label="Pieteikties: <?= e($s['title']) ?>">Pieteikties <?= icon('arrow') ?></a>
          <?php else: ?>
            <p class="sold-out">Vietu nav</p>
          <?php endif; ?>
        </div>
      </article>
      <button type="button" class="note-restore" data-note-restore hidden><?= e($s['title']) ?> · atvērt piezīmi</button>
      <?php endforeach; ?>
    </div>
    <?php endif; ?>
    <p class="small section-foot">Atcelšanas nosacījumi: <a href="<?= url('atmaksa') ?>">atmaksas politika</a>.</p>
  </div>
</section>

<section class="section" aria-labelledby="h-ka">
  <div class="wrap">
    <div class="section-head"><h2 id="h-ka">Kā pieteikties</h2></div>
    <ol class="steps">
      <li><h3>Aizpildiet pieteikumu</h3><p>Izvēlieties maiņu un ierakstiet dalībnieka datus. Tas vēl nav maksājums.</p></li>
      <li><h3>Saņemiet rēķinu</h3><p>2 darba dienu laikā nosūtām rēķinu uz jūsu e-pastu. Vieta ir rezervēta 7 dienas.</p></li>
      <li><h3>Apmaksājiet un brauciet</h3><p>Pēc apmaksas vieta ir apstiprināta. Pirmajā dienā pastāstiet instruktoram par bērna veselību.</p></li>
    </ol>
  </div>
</section>
<?php
    page_end();
}

/* ---------- Pieteikšanās ---------- */
function page_pieteikties(): void
{
    $sessions = db()->query('SELECT * FROM mk_camp_sessions WHERE active = 1 ORDER BY start_date')->fetchAll();
    $levels = ['iesācējs' => 'Iesācējs (nav slēpojis)', 'vidējs' => 'Vidējs (slēpo zaļās/zilās trases)', 'pieredzējis' => 'Pieredzējis (slēpo sarkanās trases)'];
    $errors = [];
    $done = null;
    // Vācam tikai to, kas vajadzīgs nometnes organizēšanai un saziņai ar vecākiem.
    $v = [
        'session_id'       => (int)($_POST['session_id'] ?? $_GET['session'] ?? 0),
        'participant_name' => trim((string)($_POST['participant_name'] ?? '')),
        'participant_age'  => trim((string)($_POST['participant_age'] ?? '')),
        'ski_level'        => (string)($_POST['ski_level'] ?? ''),
        'parent_name'      => trim((string)($_POST['parent_name'] ?? '')),
        'email'            => trim((string)($_POST['email'] ?? '')),
        'phone'            => trim((string)($_POST['phone'] ?? '')),
        'food_notes'       => trim((string)($_POST['food_notes'] ?? '')),
    ];
    // papildu pakalpojumi: tikai tad, ja vecāks pats atzīmē
    $wantRental = !empty($_POST['want_rental']);
    $wantHotel = !empty($_POST['want_hotel']);

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        csrf_check();
        if (($_POST['website'] ?? '') !== '') { http_response_code(400); exit; } // surogātpasta slazds

        $session = null;
        foreach ($sessions as $s) if ((int)$s['id'] === $v['session_id']) $session = $s;
        if (!$session) $errors['session_id'] = 'Izvēlieties maiņu.';
        if (mb_strlen($v['participant_name']) < 2 || mb_strlen($v['participant_name']) > 100) $errors['participant_name'] = 'Ievadiet dalībnieka vārdu un uzvārdu.';
        if (!ctype_digit($v['participant_age']) || (int)$v['participant_age'] < 7 || (int)$v['participant_age'] > 16) $errors['participant_age'] = 'Vecumam jābūt no 7 līdz 16 gadiem.';
        if (!isset($levels[$v['ski_level']])) $errors['ski_level'] = 'Izvēlieties slēpošanas līmeni.';
        if (mb_strlen($v['parent_name']) < 2 || mb_strlen($v['parent_name']) > 100) $errors['parent_name'] = 'Ievadiet vecāka vai aizbildņa vārdu un uzvārdu.';
        if (!filter_var($v['email'], FILTER_VALIDATE_EMAIL) || strlen($v['email']) > 254) $errors['email'] = 'Ievadiet derīgu e-pasta adresi.';
        if (!preg_match('/^\+?[0-9 ]{8,15}$/', $v['phone'])) $errors['phone'] = 'Ievadiet derīgu tālruņa numuru, piem., +371 20000000.';
        if (mb_strlen($v['food_notes']) > 500) $errors['food_notes'] = 'Ēdināšanas norādēm jābūt ne garākām par 500 rakstzīmēm.';
        // veselības dati (piem., alerģijas) — tikai ar atsevišķu, nepārprotamu piekrišanu (VDAR 9.2.a)
        if ($v['food_notes'] !== '' && empty($_POST['food_consent'])) $errors['food_consent'] = 'Lai saglabātu ēdināšanas norādes, atzīmējiet piekrišanu — vai izdzēsiet norādes.';
        if (empty($_POST['accept_terms'])) $errors['accept_terms'] = 'Lai pieteiktos, jāapstiprina, ka esat iepazinies ar noteikumiem.';

        if (!$errors) {
            $pdo = db();
            $pdo->beginTransaction();
            // maiņas rinda tiek bloķēta, lai divi vienlaicīgi pieteikumi neaizņemtu pēdējo vietu abi
            $pdo->prepare('SELECT id FROM mk_camp_sessions WHERE id = ? FOR UPDATE')->execute([$session['id']]);
            if (seats_taken((int)$session['id']) >= (int)$session['capacity']) {
                $pdo->rollBack();
                $errors['session_id'] = 'Diemžēl šajā maiņā vairs nav brīvu vietu.';
            } else {
                $code = strtoupper(substr(bin2hex(random_bytes(6)), 0, 10));
                $rental = $wantRental && (int)$session['rental_cents'] > 0;   // summu vienmēr rēķina serveris, ne pārlūks
                $hotel = $wantHotel && (int)$session['hotel_cents'] > 0;
                $lines = price_lines($session, $rental, $hotel, (int)$v['participant_age']);
                $total = end($lines)[1];
                $pdo->prepare('INSERT INTO mk_registrations (session_id, code, participant_name, participant_age, ski_level, parent_name, email, phone, food_notes, food_consent_at, want_rental, want_hotel, total_cents, terms_version, consent_at, created_at)
                               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)')
                    ->execute([$session['id'], $code, $v['participant_name'], (int)$v['participant_age'], $v['ski_level'], $v['parent_name'], $v['email'], $v['phone'],
                               $v['food_notes'] !== '' ? $v['food_notes'] : null, $v['food_notes'] !== '' ? now() : null,
                               (int)$rental, (int)$hotel, $total, cfg('policy_updated'), now(), now()]);
                $pdo->commit();
                $mailed = mail_registration($v + ['code' => $code, 'title' => $session['title'], 'start_date' => $session['start_date'], 'end_date' => $session['end_date'], 'lines' => $lines]);
                if (filter_var((string)cfg('mail_notify'), FILTER_VALIDATE_EMAIL)) {   // paziņojums jums — bez personas datiem
                    send_mail((string)cfg('mail_notify'), "Jauns pieteikums $code", "Saņemts jauns pieteikums.\n\nKods: $code\nMaiņa: {$session['title']}\n\nSkatīt un nosūtīt rēķinu: administrācija → Pieteikumi.");
                }
                $_SESSION['reg_done'] = ['code' => $code, 'title' => $session['title'], 'price' => $total, 'lines' => $lines, 'mailed' => $mailed];
                redirect(url('pieteikties', ['ok' => 1]));   // pārlādējot lapu, pieteikums netiek iesniegts atkārtoti
            }
        }
    }
    if (isset($_GET['ok']) && !empty($_SESSION['reg_done'])) { $done = $_SESSION['reg_done']; unset($_SESSION['reg_done']); }

    page_start('Pieteikšanās', 'pieteikties');
    $months = [1 => 'janvāris', 'februāris', 'marts', 'aprīlis', 'maijs', 'jūnijs', 'jūlijs', 'augusts', 'septembris', 'oktobris', 'novembris', 'decembris'];
    $noteTitle = $done ? 'Pieteikums saņemts' : 'Pieteikšanās nometnei';
    ?>
<div class="wrap note-page">
<article class="note note-form" data-note aria-labelledby="note-form-title">
  <div class="note-bar">
    <div class="lights">
      <a class="light light-close" href="<?= url() ?>" aria-label="Aizvērt — atpakaļ uz sākumu"><svg viewBox="0 0 8 8" aria-hidden="true"><path d="M2 2l4 4M6 2L2 6"/></svg></a>
      <button type="button" class="light light-min" data-note-act="min" aria-label="Minimizēt piezīmi" aria-expanded="true"><svg viewBox="0 0 8 8" aria-hidden="true"><path d="M1.5 4h5"/></svg></button>
      <button type="button" class="light light-max" data-note-act="max" aria-label="Maksimizēt piezīmi" aria-pressed="false"><svg viewBox="0 0 8 8" aria-hidden="true"><path d="M4 1.5v5M1.5 4h5"/></svg></button>
    </div>
    <p class="note-bar-title" aria-hidden="true"><?= e($noteTitle) ?></p>
  </div>
  <div class="note-body">
  <p class="note-date"><time datetime="<?= e(date('Y-m-d\TH:i')) ?>"><?= (int)date('j') ?>. <?= e($months[(int)date('n')]) ?> <?= e(date('Y')) ?>, <?= e(date('H:i')) ?></time></p>
<?php if ($done): ?>
  <h1 class="note-title" id="note-form-title">Pieteikums saņemts</h1>
  <div class="notice" role="status">
    <p><strong><?= e($done['title']) ?></strong> · apmaksai <strong class="num"><?= e(money($done['price'])) ?></strong> ar PVN</p>
    <?php if (count($done['lines'] ?? []) > 2): ?>
    <ul class="sum-lines"><?php foreach (array_slice($done['lines'], 0, -1) as $l): ?><li><span><?= e($l[0]) ?></span> <span class="num"><?= e(money($l[1])) ?></span></li><?php endforeach; ?></ul>
    <?php endif; ?>
    <?php if (!empty($done['mailed'])): ?><p>Apstiprinājumu ar šo informāciju nosūtījām uz jūsu e-pastu. Ja to neredzat, pārbaudiet mēstuļu mapi.</p><?php endif; ?>
    <p>2 darba dienu laikā nosūtīsim rēķinu uz jūsu e-pastu. Vieta ir rezervēta 7 dienas līdz rēķina apmaksai.</p>
  </div>
  <div>
    <p class="small">Pieteikuma kods — saglabājiet to atsauksmei vai datu dzēšanai</p>
    <div class="code-row">
      <span class="code-big" id="reg-code"><?= e($done['code']) ?></span>
      <button type="button" class="btn" data-copy="#reg-code" data-copied-text="Nokopēts"><?= icon('copy', 'icon-copy') ?><?= icon('check', 'icon-check') ?><span aria-live="polite">Kopēt</span></button>
    </div>
  </div>
  <p><a class="textlink" href="<?= url() ?>">Uz sākumu</a></p>
<?php else: ?>
  <h1 class="note-title" id="note-form-title">Pieteikšanās nometnei</h1>
  <p>Lauki ir obligāti, ja nav norādīts citādi. Ēdināšanas vajadzības varat uzrakstīt zemāk; citu informāciju par veselību lūdzam nodot instruktoram klātienē pirmajā dienā.</p>

  <?php if ($errors): ?>
    <div class="errors" role="alert" tabindex="-1" id="kludas">
      <p><strong>Lūdzu, izlabojiet kļūdas (<?= count($errors) ?>):</strong></p>
      <ul><?php foreach ($errors as $k => $msg): ?><li><a href="#f-<?= e($k) ?>"><?= e($msg) ?></a></li><?php endforeach; ?></ul>
    </div>
  <?php endif; ?>

  <?php if (!$sessions): ?>
    <p>Šobrīd nav atvērtu maiņu.</p>
  <?php else: ?>
  <form method="post" action="<?= url('pieteikties') ?>" class="stack" novalidate>
    <?= csrf_field() ?>
    <div class="hp" aria-hidden="true"><label>Neaizpildīt <input type="text" name="website" tabindex="-1" autocomplete="off"></label></div>

    <div>
      <label for="f-session_id">Maiņa</label>
      <select id="f-session_id" name="session_id" required<?= aria_err($errors, 'session_id') ?>>
        <option value="">— izvēlieties —</option>
        <?php foreach ($sessions as $s): $left = max(0, (int)$s['capacity'] - seats_taken((int)$s['id'])); ?>
          <option value="<?= (int)$s['id'] ?>" data-price="<?= (int)$s['price_cents'] ?>" data-price16="<?= (int)$s['price16_cents'] ?>" data-rental="<?= (int)$s['rental_cents'] ?>" data-hotel="<?= (int)$s['hotel_cents'] ?>" data-hotel-label="<?= e(hotel_label($s)) ?>"<?= $v['session_id'] === (int)$s['id'] ? ' selected' : '' ?><?= $left ? '' : ' disabled' ?>>
            <?= e($s['title']) ?> — <?= e(money((int)$s['price_cents'])) ?> ar PVN<?= $left ? '' : ' (vietu nav)' ?>
          </option>
        <?php endforeach; ?>
      </select>
      <?= field_error($errors, 'session_id') ?>
    </div>

    <?php $anyExtras = (bool)array_filter($sessions, fn($s) => (int)$s['rental_cents'] > 0 || (int)$s['hotel_cents'] > 0); ?>
    <?php if ($anyExtras): ?>
    <fieldset id="f-extras" data-extras>
      <legend>Papildu pakalpojumi <span class="hint">Pēc izvēles — nekas nav atzīmēts iepriekš. Cena pieskaitās kopsummai.</span></legend>
      <!-- Rūtiņas NAV atzīmētas iepriekš. -->
      <label class="check" data-extra="rental"><input type="checkbox" id="f-want_rental" name="want_rental" value="1"<?= $wantRental ? ' checked' : '' ?>> <span>Inventāra noma <strong class="num" data-extra-price></strong></span></label>
      <label class="check" data-extra="hotel"><input type="checkbox" id="f-want_hotel" name="want_hotel" value="1"<?= $wantHotel ? ' checked' : '' ?>> <span><span data-hotel-label>Viesnīca</span> <strong class="num" data-extra-price></strong></span></label>
      <noscript><p class="small">Papildu pakalpojumu cenas ir norādītas pie katras maiņas sākumlapā.</p></noscript>
    </fieldset>
    <?php endif; ?>

    <div>
      <label for="f-participant_name">Dalībnieka vārds, uzvārds</label>
      <input type="text" id="f-participant_name" name="participant_name" value="<?= e($v['participant_name']) ?>" required maxlength="100"<?= aria_err($errors, 'participant_name') ?>>
      <?= field_error($errors, 'participant_name') ?>
    </div>

    <div>
      <label for="f-participant_age">Dalībnieka vecums <span class="hint">Pilni gadi nometnes sākumā (7–16). Dzimšanas datumu neprasām.</span></label>
      <input type="number" id="f-participant_age" name="participant_age" min="7" max="16" inputmode="numeric" value="<?= e($v['participant_age']) ?>" required<?= aria_err($errors, 'participant_age') ?>>
      <?= field_error($errors, 'participant_age') ?>
      <p class="small" hidden data-age-note style="margin-top:var(--s2)">No 16 gadiem pacēlājam vajadzīga standarta biļete, tāpēc pamatcena ir <strong class="num" data-age-price></strong>.</p>
    </div>

    <fieldset id="f-ski_level"<?= isset($errors['ski_level']) ? ' aria-describedby="err-ski_level"' : '' ?>>
      <legend>Slēpošanas līmenis <span class="hint">Lai sadalītu grupās</span></legend>
      <div class="levels">
      <?php $li = 0; foreach ($levels as $key => $label): ?>
        <label class="check level"><input type="radio" name="ski_level" value="<?= e($key) ?>"<?= $v['ski_level'] === $key ? ' checked' : '' ?>> <span class="piste piste-<?= $li++ ?>" aria-hidden="true"></span> <?= e($label) ?></label>
      <?php endforeach; ?>
      </div>
      <?= field_error($errors, 'ski_level') ?>
    </fieldset>

    <div>
      <label for="f-parent_name">Vecāka vai aizbildņa vārds, uzvārds</label>
      <input type="text" id="f-parent_name" name="parent_name" autocomplete="name" value="<?= e($v['parent_name']) ?>" required maxlength="100"<?= aria_err($errors, 'parent_name') ?>>
      <?= field_error($errors, 'parent_name') ?>
    </div>

    <div>
      <label for="f-email">E-pasts <span class="hint">Rēķinam un nometnes informācijai. Reklāmas nesūtām.</span></label>
      <input type="email" id="f-email" name="email" autocomplete="email" value="<?= e($v['email']) ?>" required<?= aria_err($errors, 'email') ?>>
      <?= field_error($errors, 'email') ?>
    </div>

    <div>
      <label for="f-phone">Tālrunis <span class="hint">Saziņai nometnes laikā ārkārtas gadījumā</span></label>
      <input type="tel" id="f-phone" name="phone" autocomplete="tel" value="<?= e($v['phone']) ?>" required<?= aria_err($errors, 'phone') ?>>
      <?= field_error($errors, 'phone') ?>
    </div>

    <div>
      <label for="f-food_notes">Ēdināšanas norādes <span class="hint">Nav obligāts. Piem., “veģetārietis”, “alerģija pret riekstiem”, “bez laktozes”. Rakstiet tikai to, kas vajadzīgs ēdināšanai.</span></label>
      <textarea id="f-food_notes" name="food_notes" maxlength="500" rows="3" data-food-notes<?= aria_err($errors, 'food_notes') ?>><?= e($v['food_notes']) ?></textarea>
      <?= field_error($errors, 'food_notes') ?>
      <!-- Piekrišana NAV atzīmēta iepriekš; vajadzīga tikai tad, ja norādes ir aizpildītas. -->
      <label class="check" for="f-food_consent" data-food-consent<?= $v['food_notes'] === '' && !isset($errors['food_consent']) ? ' hidden' : '' ?>>
        <input type="checkbox" id="f-food_consent" name="food_consent" value="1"<?= !empty($_POST['food_consent']) ? ' checked' : '' ?><?= aria_err($errors, 'food_consent') ?>>
        <span>Piekrītu, ka šīs norādes tiek saglabātas un nodotas nometnes darbiniekiem, kas gādā par ēdināšanu. Piekrišanu varat atsaukt jebkurā laikā.</span>
      </label>
      <?= field_error($errors, 'food_consent') ?>
    </div>

    <div>
      <!-- Izvēles rūtiņa NAV atzīmēta iepriekš. -->
      <label class="check" for="f-accept_terms">
        <input type="checkbox" id="f-accept_terms" name="accept_terms" value="1"<?= aria_err($errors, 'accept_terms') ?>>
        <span>Esmu iepazinies ar <a href="<?= url('noteikumi') ?>" target="_blank" rel="noopener">noteikumiem (atveras jaunā cilnē)</a> un <a href="<?= url('atmaksa') ?>" target="_blank" rel="noopener">atmaksas politiku (atveras jaunā cilnē)</a> un piekrītu tiem.</span>
      </label>
      <?= field_error($errors, 'accept_terms') ?>
    </div>

    <p class="small">Jūsu datus apstrādājam līguma izpildei, kā aprakstīts <a href="<?= url('privatums') ?>">privātuma politikā</a>. Dati tiek dzēsti <?= (int)cfg('retention_months') ?> mēnešus pēc nometnes, un jūs tos varat dzēst jebkurā laikā <a href="<?= url('mani-dati') ?>">šeit</a>.</p>

    <p class="total" aria-live="polite" hidden data-total-row>Kopā apmaksai: <strong class="num" data-total></strong> <span class="small">ar PVN</span></p>

    <div>
      <button type="submit" class="btn btn-primary btn-lg btn-block" data-busy-text="Sūta pieteikumu…">Nosūtīt pieteikumu <?= icon('arrow') ?></button>
      <p class="small" style="margin-top:var(--s2)">Tas vēl nav maksājums. Rēķina summa būs maiņas cena un tikai tie papildu pakalpojumi, kurus atzīmējāt.</p>
    </div>
  </form>
  <?php endif; ?>
<?php endif; ?>
  </div>
</article>
</div>
<?php
    page_end();
}

/* ---------- Atsauksmes ---------- */
function page_atsauksmes(): void
{
    // Atsauksmes var atstāt TIKAI reāli dalībnieki (ar pieteikuma kodu) pēc maiņas sākuma.
    // Administrators var tikai publicēt vai noraidīt (ar iemeslu), bet NEVAR rediģēt tekstu.
    $errors = [];
    $v = ['code' => '', 'author' => '', 'rating' => '', 'body' => ''];

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        csrf_check();
        foreach ($v as $k => $_) $v[$k] = trim((string)($_POST[$k] ?? ''));
        $reg = null;
        if ($v['code'] !== '') {
            $st = db()->prepare("SELECT r.id FROM mk_registrations r JOIN mk_camp_sessions s ON s.id = r.session_id
                                 WHERE r.code = ? AND r.status != 'atcelts' AND s.start_date <= ?");
            $st->execute([strtoupper($v['code']), date('Y-m-d')]);
            $reg = $st->fetch();
        }
        if (!$reg) $errors['code'] = 'Kods nav atrasts vai nometne vēl nav sākusies. Atsauksmi var atstāt tikai dalībnieks pēc nometnes sākuma.';
        if (mb_strlen($v['author']) < 2 || mb_strlen($v['author']) > 40) $errors['author'] = 'Ievadiet vārdu (piem., “Ilze, mamma”).';
        if (!in_array($v['rating'], ['1', '2', '3', '4', '5'], true)) $errors['rating'] = 'Izvēlieties vērtējumu.';
        if (mb_strlen($v['body']) < 10 || mb_strlen($v['body']) > 2000) $errors['body'] = 'Atsauksmei jābūt 10–2000 rakstzīmes garai.';
        if (!$errors) {
            $dup = db()->prepare('SELECT COUNT(*) FROM mk_reviews WHERE registration_id = ?');
            $dup->execute([$reg['id']]);
            if ((int)$dup->fetchColumn() > 0) {
                $errors['code'] = 'Ar šo kodu atsauksme jau ir iesniegta.';
            } else {
                db()->prepare('INSERT INTO mk_reviews (registration_id, author, rating, body, created_at) VALUES (?,?,?,?,?)')
                    ->execute([$reg['id'], $v['author'], (int)$v['rating'], $v['body'], now()]);
                flash('Paldies! Atsauksme tiks publicēta pēc pārbaudes (parasti 2 darba dienu laikā).');
                redirect(url('atsauksmes'));
            }
        }
    }

    $reviews = db()->query("SELECT author, rating, body, created_at FROM mk_reviews WHERE status = 'publicēta' ORDER BY created_at DESC")->fetchAll();
    $avg = $reviews ? array_sum(array_column($reviews, 'rating')) / count($reviews) : null;

    page_start('Atsauksmes', 'atsauksmes');
    ?>
<div class="wrap page panel-l">
  <h1>Dalībnieku atsauksmes</h1>
  <p>Šeit redzamas tikai pārbaudītu dalībnieku atsauksmes. Mēs nemaksājam par atsauksmēm, nerediģējam to tekstu un publicējam arī kritiskas atsauksmes. Atsauksme var tikt noraidīta tikai tad, ja tajā ir aizskarošs saturs, personas dati vai reklāma.</p>

  <?php if (!$reviews): ?>
    <p>Atsauksmju vēl nav.</p>
  <?php else: ?>
    <div class="rating-summary"><span class="num"><?= e(number_format($avg, 1, ',', '')) ?></span><span class="stars" aria-hidden="true"><?= str_repeat('★', (int)round($avg)) . str_repeat('☆', 5 - (int)round($avg)) ?></span><span class="small">vidēji no <?= count($reviews) ?> <?= count($reviews) === 1 ? 'atsauksmes' : 'atsauksmēm' ?></span></div>
    <?php foreach ($reviews as $r): ?>
      <article class="review">
        <p class="stars" role="img" aria-label="Vērtējums: <?= (int)$r['rating'] ?> no 5"><?= str_repeat('★', (int)$r['rating']) . str_repeat('☆', 5 - (int)$r['rating']) ?></p>
        <p><?= nl2br(e($r['body'])) ?></p>
        <p class="small"><?= e($r['author']) ?> · <time class="num" datetime="<?= e(substr($r['created_at'], 0, 7)) ?>"><?= e(date('m.Y', strtotime($r['created_at']))) ?></time></p>
      </article>
    <?php endforeach; ?>
  <?php endif; ?>

  <h2>Atstāt atsauksmi</h2>
  <?php if ($errors): ?>
    <div class="errors" role="alert" tabindex="-1" id="kludas"><ul>
      <?php foreach ($errors as $k => $m): ?><li><a href="#r-<?= e($k) ?>"><?= e($m) ?></a></li><?php endforeach; ?>
    </ul></div>
  <?php endif; ?>
  <form method="post" action="<?= url('atsauksmes') ?>" class="stack" novalidate>
    <?= csrf_field() ?>
    <div><label for="r-code">Pieteikuma kods <span class="hint">Norādīts pieteikuma apstiprinājumā</span></label>
      <input type="text" id="r-code" name="code" value="<?= e($v['code']) ?>" autocomplete="off" required<?= aria_err($errors, 'code') ?>></div>
    <div><label for="r-author">Vārds, kas tiks publicēts <span class="hint">Nenorādiet uzvārdu vai bērna vārdu</span></label>
      <input type="text" id="r-author" name="author" value="<?= e($v['author']) ?>" maxlength="40" required<?= aria_err($errors, 'author') ?>></div>
    <fieldset id="r-rating"><legend>Vērtējums</legend>
      <div class="stars-input">
      <?php for ($i = 1; $i <= 5; $i++): ?>
        <label class="check"><input type="radio" name="rating" value="<?= $i ?>"<?= $v['rating'] === (string)$i ? ' checked' : '' ?>> <?= $i ?></label>
      <?php endfor; ?>
      </div>
    </fieldset>
    <div><label for="r-body">Atsauksme</label>
      <textarea id="r-body" name="body" maxlength="2000" required<?= aria_err($errors, 'body') ?>><?= e($v['body']) ?></textarea></div>
    <p><button class="btn btn-primary" type="submit" data-busy-text="Iesniedz…">Iesniegt atsauksmi</button></p>
  </form>
</div>
<?php
    page_end();
}

/* ---------- Mani dati ---------- */
function page_mani_dati(): void
{
    $errors = [];
    $result = null;
    $email = trim((string)($_POST['email'] ?? ''));
    $code = strtoupper(trim((string)($_POST['code'] ?? '')));
    $action = (string)($_POST['action'] ?? '');

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        csrf_check();
        if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 254) $errors[] = 'Ievadiet derīgu e-pasta adresi.';

        if (!$errors && $action === 'delete_now') {
            // E-pasts + pieteikuma kods kopā apliecina, ka dati pieder pieprasītājam.
            $st = db()->prepare('SELECT COUNT(*) FROM mk_registrations WHERE email = ? AND code = ?');
            $st->execute([$email, $code]);
            if ((int)$st->fetchColumn() === 0) {
                $errors[] = 'E-pasts un kods nesakrīt. Ja kodu neatceraties, izmantojiet pieprasījuma formu zemāk.';
            } elseif (empty($_POST['confirm'])) {
                $errors[] = 'Apstipriniet, ka saprotat — dzēšanu nevar atsaukt.';
            } else {
                $n = delete_personal_data($email);
                audit('lietotājs', "Pašapkalpošanās dzēšana: dzēsti $n pieteikumi");
                $result = "Dzēsts. Visi ar šo e-pastu saistītie pieteikumi ($n) un atsauksmes ir neatgriezeniski izdzēsti. Grāmatvedības dokumentus (rēķinus) likums mums liek glabāt atsevišķi — sk. privātuma politiku.";
            }
        }

        if (!$errors && $action === 'request') {
            $msg = mb_substr(trim((string)($_POST['message'] ?? '')), 0, 1000);
            db()->prepare('INSERT INTO mk_deletion_requests (email, message, created_at) VALUES (?,?,?)')->execute([$email, $msg, now()]);
            $result = 'Pieprasījums saņemts. Pārbaudīsim jūsu identitāti, sazinoties ar jums uz norādīto e-pastu, un izpildīsim pieprasījumu ne vēlāk kā 30 dienu laikā.';
        }
    }

    page_start('Mani dati un datu dzēšana');
    ?>
<div class="wrap page panel-l">
  <h1>Mani dati un datu dzēšana</h1>
  <p>Jums ir tiesības piekļūt saviem datiem, tos labot un dzēst (VDAR 15.–17. pants). Šeit varat dzēst savus pieteikuma datus pats vai nosūtīt mums pieprasījumu.</p>

  <?php if ($result): ?><p class="notice" role="status"><?= e($result) ?></p><?php endif; ?>
  <?php if ($errors): ?>
    <div class="errors" role="alert" tabindex="-1" id="kludas"><ul><?php foreach ($errors as $m): ?><li><?= e($m) ?></li><?php endforeach; ?></ul></div>
  <?php endif; ?>

  <h2>1. Dzēst datus tūlīt</h2>
  <p>Ievadiet e-pastu un pieteikuma kodu. Tiks dzēsti visi ar šo e-pastu saistītie pieteikumi un atsauksmes. Ja dalība vēl nav notikusi, tas nozīmē arī pieteikuma atcelšanu — atmaksu skatiet <a href="<?= url('atmaksa') ?>">atmaksas politikā</a>.</p>
  <form method="post" action="<?= url('mani-dati') ?>" class="stack" data-confirm="Vai tiešām dzēst visus savus datus? Šo darbību nevar atsaukt.">
    <?= csrf_field() ?>
    <input type="hidden" name="action" value="delete_now">
    <div><label for="d-email">E-pasts</label><input type="email" id="d-email" name="email" autocomplete="email" required></div>
    <div><label for="d-code">Pieteikuma kods</label><input type="text" id="d-code" name="code" autocomplete="off" required></div>
    <label class="check"><input type="checkbox" name="confirm" value="1"> <span>Saprotu, ka dzēšana ir neatgriezeniska.</span></label>
    <p><button class="btn btn-danger" type="submit" data-busy-text="Dzēš…">Dzēst manus datus</button></p>
  </form>

  <h2>2. Pieprasījums bez koda (piekļuve, labošana vai dzēšana)</h2>
  <form method="post" action="<?= url('mani-dati') ?>" class="stack">
    <?= csrf_field() ?>
    <input type="hidden" name="action" value="request">
    <div><label for="q-email">E-pasts, kuru norādījāt pieteikumā</label><input type="email" id="q-email" name="email" autocomplete="email" required></div>
    <div><label for="q-msg">Ko vēlaties darīt? <span class="hint">Piem., “dzēst visus datus”, “izsūtīt manu datu kopiju” vai “dzēst ēdināšanas norādes”</span></label><textarea id="q-msg" name="message" maxlength="1000"></textarea></div>
    <p><button class="btn btn-primary" type="submit" data-busy-text="Sūta…">Nosūtīt pieprasījumu</button></p>
  </form>
  <p>Varat arī rakstīt: <a href="mailto:<?= e(cfg('dpo_email')) ?>"><?= e(cfg('dpo_email')) ?></a>.</p>
</div>
<?php
    page_end();
}

/* ---------- Kontakti ---------- */
function page_kontakti(): void
{
    page_start('Kontakti un rekvizīti', 'kontakti');
    ?>
<div class="wrap page panel-l">
  <h1>Kontakti un uzņēmuma rekvizīti</h1>
  <table>
    <tbody>
      <tr><th scope="row">Pakalpojuma sniedzējs</th><td><?= e(cfg('company_name')) ?></td></tr>
      <tr><th scope="row">Reģistrācijas numurs</th><td><?= e(cfg('reg_number')) ?></td></tr>
      <tr><th scope="row">PVN numurs</th><td><?= e(cfg('vat_number')) ?></td></tr>
      <tr><th scope="row">Juridiskā adrese</th><td><?= e(cfg('legal_address')) ?></td></tr>
      <tr><th scope="row">Nometnes norises vieta</th><td><?= e(cfg('camp_address')) ?></td></tr>
      <tr><th scope="row">Bankas konts</th><td><?= e(cfg('bank')) ?></td></tr>
      <tr><th scope="row">E-pasts</th><td><a href="mailto:<?= e(cfg('email')) ?>"><?= e(cfg('email')) ?></a></td></tr>
      <tr><th scope="row">Tālrunis</th><td><a href="tel:<?= e(str_replace(' ', '', cfg('phone'))) ?>"><?= e(cfg('phone')) ?></a></td></tr>
      <tr><th scope="row">Datu aizsardzības jautājumi</th><td><a href="mailto:<?= e(cfg('dpo_email')) ?>"><?= e(cfg('dpo_email')) ?></a></td></tr>
    </tbody>
  </table>
  <h2>Strīdu risināšana</h2>
  <p>Sūdzības lūdzam sūtīt uz <?= e(cfg('email')) ?>; atbildēsim 14 dienu laikā. Ja strīdu neizdodas atrisināt, varat vērsties Patērētāju tiesību aizsardzības centrā (<a href="https://www.ptac.gov.lv" rel="noopener">www.ptac.gov.lv</a>) vai izmantot ES strīdu izšķiršanas platformu.</p>
</div>
<?php
    page_end();
}

/* ---------- Privātuma politika ---------- */
function page_privatums(): void
{
    page_start('Privātuma politika');
    ?>
<div class="wrap page panel-l">
  <h1>Privātuma politika</h1>
  <p class="small">Spēkā no <?= e(cfg('policy_updated')) ?></p>

  <h2>1. Pārzinis</h2>
  <p><?= e(cfg('company_name')) ?>, reģ. nr. <?= e(cfg('reg_number')) ?>, <?= e(cfg('legal_address')) ?>. Saziņa par datu aizsardzību: <a href="mailto:<?= e(cfg('dpo_email')) ?>"><?= e(cfg('dpo_email')) ?></a>.</p>

  <h2>2. Kādus datus vācam un kāpēc</h2>
  <div class="table-scroll">
  <table>
    <thead><tr><th scope="col">Dati</th><th scope="col">Mērķis</th><th scope="col">Tiesiskais pamats (VDAR 6. pants)</th></tr></thead>
    <tbody>
      <tr><td>Dalībnieka vārds, uzvārds, vecums, slēpošanas līmenis</td><td>Dalības nodrošināšana, sadalīšana grupās</td><td>Līguma izpilde (6.1.b)</td></tr>
      <tr><td>Vecāka vārds, uzvārds, e-pasts, tālrunis</td><td>Rēķins, informācija par nometni, saziņa ārkārtas gadījumā</td><td>Līguma izpilde (6.1.b)</td></tr>
      <tr><td>Ēdināšanas norādes (piem., alerģijas, diēta) — tikai, ja tās norādāt</td><td>Droša ēdināšana nometnē</td><td>Jūsu nepārprotama piekrišana (6.1.a un 9.2.a), ko var atsaukt</td></tr>
      <tr><td>Rēķinu dati</td><td>Grāmatvedība</td><td>Juridisks pienākums (6.1.c)</td></tr>
      <tr><td>Atsauksmes teksts un norādītais vārds</td><td>Atsauksmju publicēšana</td><td>Jūsu piekrišana (6.1.a), ko var atsaukt</td></tr>
      <tr><td>Kļūdas ziņojums: apraksts, lapa un — ja norādāt — e-pasts</td><td>Vietnes kļūdu labošana un atbilde jums</td><td>Leģitīmās intereses (6.1.f); e-pasts — jūsu piekrišana (6.1.a)</td></tr>
      <tr><td>Sīkdatņu izvēle</td><td>Atcerēties jūsu izvēli</td><td>Leģitīmās intereses / stingri nepieciešams</td></tr>
    </tbody>
  </table>
  </div>
  <p>Mēs <strong>nevācam</strong>: personas kodu, dzimšanas datumu, citus veselības datus (izņemot ēdināšanas norādes, ja tās norādāt pats), atrašanās vietu, un neveicam profilēšanu vai automatizētu lēmumu pieņemšanu. Mēs nesūtām reklāmas e-pastus.</p>

  <h2>3. Kas saņem datus</h2>
  <p>Datus nepārdodam un nenododam reklāmas nolūkos. Datiem var piekļūt tikai:</p>
  <ul>
    <li>mūsu darbinieki un instruktori — tikai tik, cik vajadzīgs nometnes norisei (ēdināšanas norādes — tikai tie, kas gādā par ēdināšanu);</li>
    <li>tīmekļa vietnes mitināšanas pakalpojuma sniedzējs: <?= e(cfg('hosting_provider')) ?> (apstrādātājs, līgums saskaņā ar VDAR 28. pantu);</li>
    <li>grāmatvedības pakalpojumu sniedzējs: <?= e(cfg('accounting')) ?> (tikai rēķinu dati).</li>
  </ul>
  <p>Vietnē netiek izmantoti trešo pušu analītikas, reklāmas vai sociālo tīklu rīki. Dati netiek nodoti ārpus Eiropas Ekonomikas zonas.</p>

  <h2>4. Cik ilgi glabājam</h2>
  <ul>
    <li>Pieteikuma dati — <?= (int)cfg('retention_months') ?> mēnešus pēc maiņas beigām, tad tos automātiski dzēšam.</li>
    <li>Rēķini — 5 gadus, kā to nosaka Grāmatvedības likums.</li>
    <li>Atsauksmes — līdz jūs lūdzat tās dzēst.</li>
    <li>Kļūdu ziņojumi — 12 mēnešus, tad tos automātiski dzēšam.</li>
  </ul>

  <h2>5. Jūsu tiesības</h2>
  <p>Jums ir tiesības piekļūt saviem datiem, tos labot, dzēst, ierobežot apstrādi, iebilst pret apstrādi, saņemt datus pārnesamā formā un atsaukt piekrišanu. Datus varat dzēst pats lapā <a href="<?= url('mani-dati') ?>">“Mani dati”</a> vai rakstot uz <?= e(cfg('dpo_email')) ?>. Atbildēsim ne vēlāk kā 30 dienu laikā.</p>
  <p>Jums ir tiesības iesniegt sūdzību uzraudzības iestādē: <?= e(cfg('supervisory')) ?>.</p>

  <h2>6. Drošība</h2>
  <p>Vietne darbojas ar HTTPS, administratoru paroles glabājam šifrētā (hash) veidā, piekļuve administrācijas sadaļai ir ierobežota, un tiek reģistrētas administratoru darbības.</p>

  <h2>7. Izmaiņas</h2>
  <p>Par būtiskām izmaiņām informēsim šajā lapā, norādot jaunu spēkā stāšanās datumu.</p>
</div>
<?php
    page_end();
}

/* ---------- Lietošanas noteikumi ---------- */
function page_noteikumi(): void
{
    page_start('Lietošanas noteikumi');
    ?>
<div class="wrap page panel-l">
  <h1>Lietošanas un dalības noteikumi</h1>
  <p class="small">Spēkā no <?= e(cfg('policy_updated')) ?></p>

  <h2>1. Puses</h2>
  <p>Pakalpojumu sniedz <?= e(cfg('company_name')) ?>, reģ. nr. <?= e(cfg('reg_number')) ?>, <?= e(cfg('legal_address')) ?> (“Organizators”). Pieteikumu iesniedz dalībnieka vecāks vai likumīgais aizbildnis (“Klients”).</p>

  <h2>2. Pieteikšanās un līguma noslēgšana</h2>
  <ol>
    <li>Pēc pieteikuma iesniegšanas vieta tiek rezervēta uz 7 dienām.</li>
    <li>Līgums ir noslēgts, kad Klients ir apmaksājis rēķinu. Ja rēķins 7 dienu laikā netiek apmaksāts, rezervācija tiek atcelta bez maksas.</li>
    <li>Cena ir norādīta vietnē pie katras maiņas, ar PVN. Papildu maksas netiek piemērotas. Pakalpojumi, kas cenā nav iekļauti, ir skaidri norādīti pie maiņas apraksta.</li>
  </ol>

  <h2>3. Organizatora pienākumi</h2>
  <ul>
    <li>Nodrošināt programmu un instruktorus, kā norādīts maiņas aprakstā.</li>
    <li>Nekavējoties informēt Klientu par būtiskām izmaiņām programmā.</li>
    <li>Sazināties ar Klientu, ja dalībnieks gūst savainojumu vai jūtas slikti.</li>
  </ul>

  <h2>4. Klienta pienākumi</h2>
  <ul>
    <li>Sniegt patiesu informāciju par dalībnieka vecumu un slēpošanas līmeni.</li>
    <li>Pirmajā dienā klātienē informēt instruktoru par dalībnieka veselības stāvokli, kas var ietekmēt slēpošanu.</li>
    <li>Nodrošināt dalībniekam piemērotu apģērbu un ķiveri (ja ķivere nav iekļauta cenā).</li>
  </ul>

  <h2>5. Drošība un atbildība</h2>
  <p>Slēpošana ir sporta veids ar savainojumu risku. Organizators ievēro drošības prasības un atbild par zaudējumiem, kas radušies tā vainas dēļ, saskaņā ar Latvijas Republikas tiesību aktiem. Šie noteikumi neierobežo patērētāja tiesības, kas noteiktas Patērētāju tiesību aizsardzības likumā.</p>

  <h2>6. Atcelšana un atmaksa</h2>
  <p>Skatīt <a href="<?= url('atmaksa') ?>">Atmaksas politiku</a>.</p>

  <h2>7. Fotografēšana</h2>
  <p>Dalībnieku fotogrāfijas publiski izmantojam tikai ar atsevišķu, rakstisku vecāku piekrišanu, ko var atsaukt jebkurā laikā. Piekrišana nav dalības priekšnoteikums.</p>

  <h2>8. Vietnes lietošana</h2>
  <p>Vietnes saturu aizliegts izmantot komerciālos nolūkos bez atļaujas. Atsauksmēs aizliegts publicēt aizskarošu saturu, citu personu datus vai reklāmu.</p>

  <h2>9. Strīdi un piemērojamie tiesību akti</h2>
  <p>Piemēro Latvijas Republikas tiesību aktus. Strīdus risinām sarunu ceļā; ja tas neizdodas — Patērētāju tiesību aizsardzības centrā vai Latvijas tiesā.</p>
</div>
<?php
    page_end();
}

/* ---------- Atmaksas politika ---------- */
function page_atmaksa(): void
{
    page_start('Atmaksas politika');
    ?>
<div class="wrap page panel-l">
  <h1>Atcelšanas un atmaksas politika</h1>
  <p class="small">Spēkā no <?= e(cfg('policy_updated')) ?></p>
  <!-- PĀRSKATIET: procentus un termiņus pielāgojiet savam biznesam, bet saglabājiet tos skaidrus. -->

  <h2>Ja atceļat jūs</h2>
  <table>
    <thead><tr><th scope="col">Atcelšana</th><th scope="col">Atmaksa</th></tr></thead>
    <tbody>
      <tr><td>Vairāk nekā 30 dienas pirms maiņas sākuma</td><td>100%</td></tr>
      <tr><td>14–30 dienas pirms maiņas sākuma</td><td>50%</td></tr>
      <tr><td>Mazāk nekā 14 dienas pirms maiņas sākuma</td><td>0% (bet varat nodot vietu citam dalībniekam bez maksas)</td></tr>
      <tr><td>Slimības gadījumā ar ārsta izziņu</td><td>Atmaksa par neizmantotajām dienām</td></tr>
    </tbody>
  </table>
  <p>Atcelšanas maksas vai administratīvās maksas netiek ieturētas.</p>

  <h2>Ja atceļam mēs</h2>
  <p>Ja maiņu atceļam mēs (piem., sniega trūkuma, laikapstākļu vai nepietiekama dalībnieku skaita dēļ), atmaksājam 100% vai, ja vēlaties, piedāvājam vietu citā maiņā. Izvēle ir jūsu.</p>

  <h2>Atteikuma tiesības</h2>
  <!-- PĀRBAUDIET AR JURISTU: precīzu normas punktu. -->
  <p>Saskaņā ar Ministru kabineta noteikumiem Nr. 255 “Noteikumi par distances līgumu” 14 dienu atteikuma tiesības neattiecas uz brīvā laika pavadīšanas pakalpojumiem, kuru izpildei līgumā noteikts konkrēts datums. Tāpēc piedāvājam iepriekš minētos nosacījumus.</p>

  <h2>Kā pieprasīt atmaksu</h2>
  <p>Rakstiet uz <a href="mailto:<?= e(cfg('email')) ?>"><?= e(cfg('email')) ?></a>, norādot pieteikuma kodu. Atmaksu veicam uz kontu, no kura tika saņemts maksājums, 14 dienu laikā.</p>
</div>
<?php
    page_end();
}

/* ---------- Sīkdatņu politika ---------- */
function page_sikdatnes(): void
{
    page_start('Sīkdatņu politika');
    ?>
<div class="wrap page panel-l">
  <h1>Sīkdatņu politika</h1>
  <p class="small">Spēkā no <?= e(cfg('policy_updated')) ?></p>
  <p>Sīkdatnes ir nelielas teksta datnes, ko vietne saglabā jūsu ierīcē. Mēs izmantojam tikai pašu sīkdatnes; trešo pušu (reklāmas, analītikas, sociālo tīklu) sīkdatņu šajā vietnē nav.</p>

  <h2>Izmantotās sīkdatnes</h2>
  <div class="table-scroll">
  <table>
    <thead><tr><th scope="col">Nosaukums</th><th scope="col">Kategorija</th><th scope="col">Mērķis</th><th scope="col">Glabāšanas ilgums</th></tr></thead>
    <tbody>
      <tr><td><code>nometne_sid</code></td><td>Nepieciešamā</td><td>Sesija: formu drošība (CSRF aizsardzība) un administratora pieslēgšanās</td><td>Līdz pārlūka aizvēršanai</td></tr>
      <tr><td><code>cookie_consent</code></td><td>Nepieciešamā</td><td>Atceras jūsu sīkdatņu izvēli</td><td>6 mēneši</td></tr>
    </tbody>
  </table>
  </div>
  <p>Statistikas kategorija paziņojumā ir paredzēta gadījumam, ja nākotnē ieviesīsim apmeklējuma statistiku. Pašlaik neviens statistikas rīks nav uzstādīts; pirms tāda ieviešanas atjaunināsim šo tabulu.</p>

  <h2>Kā mainīt izvēli</h2>
  <p>Jūs varat jebkurā brīdī mainīt vai atsaukt savu izvēli: <button type="button" class="linklike" data-open-consent>atvērt sīkdatņu iestatījumus</button>. Sīkdatnes varat dzēst arī pārlūkprogrammas iestatījumos.</p>
</div>
<?php
    page_end();
}

/* ---------- Ziņot par kļūdu ---------- */
function page_zinot_kludu(): void
{
    $pages = ['sakums' => 'Sākums', 'pieteikties' => 'Pieteikšanās', 'atsauksmes' => 'Atsauksmes', 'mani-dati' => 'Mani dati', 'kontakti' => 'Kontakti',
              'privatums' => 'Privātuma politika', 'noteikumi' => 'Lietošanas noteikumi', 'atmaksa' => 'Atmaksas politika', 'sikdatnes' => 'Sīkdatņu politika', 'cits' => 'Cita vieta'];
    $from = (string)($_POST['page'] ?? $_GET['no'] ?? 'sakums');
    if (!isset($pages[$from])) $from = 'cits';
    $v = ['message' => trim((string)($_POST['message'] ?? '')), 'email' => trim((string)($_POST['email'] ?? ''))];
    $errors = [];
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        csrf_check();
        if (($_POST['website'] ?? '') !== '') { http_response_code(400); exit; }   // surogātpasta slazds
        // ne vairāk kā 5 ziņojumi stundā no vienas sesijas
        $recent = array_filter($_SESSION['bug_times'] ?? [], fn($t) => $t > time() - 3600);
        if (count($recent) >= 5) $errors['message'] = 'Pārāk daudz ziņojumu īsā laikā. Mēģiniet vēlreiz pēc stundas vai rakstiet mums e-pastā.';
        if (mb_strlen($v['message']) < 10 || mb_strlen($v['message']) > 2000) $errors['message'] ??= 'Aprakstiet kļūdu (10–2000 rakstzīmes).';
        if ($v['email'] !== '' && (!filter_var($v['email'], FILTER_VALIDATE_EMAIL) || strlen($v['email']) > 254)) $errors['email'] = 'Ievadiet derīgu e-pasta adresi vai atstājiet lauku tukšu.';
        if (!$errors) {
            db()->prepare('INSERT INTO mk_bug_reports (page, message, email, created_at) VALUES (?,?,?,?)')
                ->execute([$from, $v['message'], $v['email'] !== '' ? $v['email'] : null, now()]);
            $_SESSION['bug_times'] = [...$recent, time()];
            if (filter_var((string)cfg('mail_notify'), FILTER_VALIDATE_EMAIL)) {   // paziņojums jums — bez ziņotāja e-pasta
                send_mail((string)cfg('mail_notify'), 'Jauns kļūdas ziņojums: ' . $pages[$from], "Lapa: {$pages[$from]}\n\n{$v['message']}\n\nSkatīt: administrācija → Kļūdu ziņojumi.");
            }
            flash('Paldies! Kļūdas ziņojums nosūtīts.' . ($v['email'] !== '' ? ' Atbildēsim uz norādīto e-pastu.' : ''));
            redirect($from === 'cits' ? url() : url($from));
        }
    }
    page_start('Ziņot par kļūdu');
    ?>
<div class="wrap page panel-l">
  <h1>Ziņot par kļūdu</h1>
  <p>Kaut kas nedarbojas vai izskatās nepareizi? Pastāstiet mums — izlabosim. Lūdzu, nerakstiet šeit bērna datus vai veselības informāciju.</p>
  <?php if ($errors): ?>
    <div class="errors" role="alert" tabindex="-1" id="kludas"><ul><?php foreach ($errors as $k => $m): ?><li><a href="#b-<?= e($k) ?>"><?= e($m) ?></a></li><?php endforeach; ?></ul></div>
  <?php endif; ?>
  <form method="post" action="<?= url('zinot-kludu') ?>" class="stack" novalidate>
    <?= csrf_field() ?>
    <div class="hp" aria-hidden="true"><label>Neaizpildīt <input type="text" name="website" tabindex="-1" autocomplete="off"></label></div>
    <div>
      <label for="b-page">Kurā lapā?</label>
      <select id="b-page" name="page"><?php foreach ($pages as $k => $label): ?><option value="<?= e($k) ?>"<?= $from === $k ? ' selected' : '' ?>><?= e($label) ?></option><?php endforeach; ?></select>
    </div>
    <div>
      <label for="b-message">Kas notika? <span class="hint">Ko darījāt, ko gaidījāt un kas notika tā vietā. Noderīgi arī norādīt ierīci un pārlūku.</span></label>
      <textarea id="b-message" name="message" maxlength="2000" required<?= aria_err($errors, 'message') ?>><?= e($v['message']) ?></textarea>
      <?= field_error($errors, 'message') ?>
    </div>
    <div>
      <label for="b-email">E-pasts atbildei <span class="hint">Nav obligāts. Norādiet tikai tad, ja vēlaties, lai mēs atbildam.</span></label>
      <input type="email" id="b-email" name="email" autocomplete="email" value="<?= e($v['email']) ?>"<?= aria_err($errors, 'email') ?>>
      <?= field_error($errors, 'email') ?>
    </div>
    <p class="small">Ziņojumu glabājam 12 mēnešus, kā aprakstīts <a href="<?= url('privatums') ?>">privātuma politikā</a>.</p>
    <p><button class="btn btn-primary" type="submit" data-busy-text="Sūta…">Nosūtīt ziņojumu</button></p>
  </form>
</div>
<?php
    page_end();
}

function page_404(): void
{
    http_response_code(404);
    page_start('Lapa nav atrasta');
    ?>
<div class="wrap page panel-l">
  <h1>Lapa nav atrasta</h1>
  <p>Šādas lapas nav. <a href="<?= url() ?>">Atgriezties sākumā</a>.</p>
</div>
<?php
    page_end();
}

/* ============================== MARŠRUTI ================================== */
$routes = [
    'sakums' => 'page_sakums', 'pieteikties' => 'page_pieteikties', 'atsauksmes' => 'page_atsauksmes',
    'mani-dati' => 'page_mani_dati', 'kontakti' => 'page_kontakti', 'privatums' => 'page_privatums',
    'noteikumi' => 'page_noteikumi', 'atmaksa' => 'page_atmaksa', 'sikdatnes' => 'page_sikdatnes',
    'zinot-kludu' => 'page_zinot_kludu',
];
$p = (string)($_GET['p'] ?? 'sakums');
($routes[$p] ?? 'page_404')();
