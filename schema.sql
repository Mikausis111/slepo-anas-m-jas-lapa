-- Slēpošanas nometne — datubāzes tabulas (MySQL 5.7+ / MariaDB 10.3+)
-- phpMyAdmin: izvēlieties savu datubāzi → cilne "Import" → izvēlieties šo failu → "Import".
-- (Ja to neizdarīsiet, index.php izveidos tabulas pats pirmajā atvēršanas reizē.)

CREATE TABLE IF NOT EXISTS mk_camp_sessions (
  id            INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  title         VARCHAR(120) NOT NULL,
  start_date    DATE NOT NULL,
  end_date      DATE NOT NULL,
  price_cents   INT UNSIGNED NOT NULL COMMENT 'Galīgā cena ar PVN centos',
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
