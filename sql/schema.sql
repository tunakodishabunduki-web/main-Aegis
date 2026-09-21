-- ============================================================
-- Aegis Multi-Site Honeypot Schema
-- Designed to be added alongside SIMAP's existing tables.
-- Run once; all tables are prefixed with aegis_ to avoid
-- collisions with SIMAP's own schema.
-- ============================================================

-- Every website you register gets one row.
-- Must control the site (install the middleware) for it to report data.
CREATE TABLE IF NOT EXISTS aegis_sites (
    id              INT          NOT NULL AUTO_INCREMENT,
    site_url        VARCHAR(255) NOT NULL,
    site_name       VARCHAR(150) NOT NULL,
    install_key     VARCHAR(100) NOT NULL UNIQUE,
    owner_verified  TINYINT(1)   NOT NULL DEFAULT 0,
    created_at      TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_report_at  TIMESTAMP    NULL,
    PRIMARY KEY (id),
    INDEX idx_key (install_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Every suspicious event gets one row.
CREATE TABLE IF NOT EXISTS aegis_attack_log (
    id                INT          NOT NULL AUTO_INCREMENT,
    site_id           INT          NOT NULL,
    session_key       VARCHAR(64)  NOT NULL,
    ip_address        VARCHAR(45)  NOT NULL,
    user_agent        TEXT,
    browser           VARCHAR(50),
    os                VARCHAR(80),
    attack_type       ENUM(
        'FAILED_LOGIN','SQL_INJECTION_ATTEMPT','BRUTE_FORCE',
        'HONEYPOT_ROUTE_HIT','DECOY_USER_VIEWED',
        'DECOY_USER_DELETE_ATTEMPT','REAL_USER_DELETE_ATTEMPT',
        'UNAUTHORIZED_ADMIN_ACCESS','XSS_ATTEMPT','CSRF_TOKEN_MISSING',
        'RATE_LIMIT_EXCEEDED','PATH_TRAVERSAL_ATTEMPT',
        'COMMAND_INJECTION_ATTEMPT','XXE_ATTEMPT',
        'OPEN_REDIRECT_ATTEMPT','SSRF_ATTEMPT',
        'NOSQL_INJECTION_ATTEMPT','JWT_TAMPERING_ATTEMPT',
        'PARAMETER_POLLUTION_ATTEMPT','SCANNER_TOOL_DETECTED',
        -- Python module detections
        'THREAT_INTEL_IOC_MATCH','DECEPTION_HONEYTOKEN_TRIGGER',
        'NETWORK_PORT_SCAN','NETWORK_DNS_ANOMALY'
    ) NOT NULL,
    entered_username  VARCHAR(255),   -- exactly what was typed (forensics)
    entered_password  VARCHAR(255),   -- stored as-is intentionally (bait data only)
    endpoint          VARCHAR(255),
    payload           TEXT,           -- raw JSON of the request body/query
    severity_score    TINYINT UNSIGNED NOT NULL DEFAULT 0,
    source            ENUM('php','python') NOT NULL DEFAULT 'php',
    created_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    FOREIGN KEY (site_id) REFERENCES aegis_sites(id) ON DELETE CASCADE,
    INDEX idx_site        (site_id),
    INDEX idx_session     (session_key),
    INDEX idx_ip          (ip_address),
    INDEX idx_attack_type (attack_type),
    INDEX idx_created     (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- One row per unique attacker per site.
CREATE TABLE IF NOT EXISTS aegis_attacker_profile (
    site_id        INT         NOT NULL,
    session_key    VARCHAR(64) NOT NULL,
    ip_address     VARCHAR(45),
    user_agent     TEXT,
    browser        VARCHAR(50),
    os             VARCHAR(80),
    first_seen     TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen      TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP
                               ON UPDATE CURRENT_TIMESTAMP,
    total_attempts INT UNSIGNED NOT NULL DEFAULT 0,
    max_severity   TINYINT UNSIGNED NOT NULL DEFAULT 0,
    is_banned      TINYINT(1)  NOT NULL DEFAULT 0,
    banned_at      TIMESTAMP   NULL,
    ban_reason     VARCHAR(255),
    PRIMARY KEY (site_id, session_key),
    FOREIGN KEY (site_id) REFERENCES aegis_sites(id) ON DELETE CASCADE,
    INDEX idx_ip       (ip_address),
    INDEX idx_banned   (is_banned),
    INDEX idx_severity (max_severity)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Decoy/fake users, scoped per site.
-- Shown only to flagged sessions — never to real users.
CREATE TABLE IF NOT EXISTS aegis_decoy_users (
    id              INT          NOT NULL AUTO_INCREMENT,
    site_id         INT          NOT NULL,
    fake_username   VARCHAR(50)  NOT NULL,
    fake_email      VARCHAR(100) NOT NULL,
    fake_role       VARCHAR(50)  NOT NULL DEFAULT 'User',
    fake_created_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    FOREIGN KEY (site_id) REFERENCES aegis_sites(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Stores results/snapshots from Python security modules.
CREATE TABLE IF NOT EXISTS aegis_python_events (
    id          INT          NOT NULL AUTO_INCREMENT,
    module      ENUM('threat_intelligence','deception_grid','network_forensics') NOT NULL,
    event_type  VARCHAR(100) NOT NULL,
    indicator   VARCHAR(255),          -- IP / domain / hash / token ID
    detail      TEXT,                  -- JSON payload from the Python module
    severity    ENUM('Low','Medium','High','Critical') NOT NULL DEFAULT 'Medium',
    site_id     INT          NULL,     -- optional: link to a registered site
    created_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    FOREIGN KEY (site_id) REFERENCES aegis_sites(id) ON DELETE SET NULL,
    INDEX idx_module   (module),
    INDEX idx_severity (severity),
    INDEX idx_created  (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================
-- Seed data: two demo sites and their decoy users.
-- Remove or replace before deploying in production.
-- ============================================================

INSERT IGNORE INTO aegis_sites (site_url, site_name, install_key, owner_verified) VALUES
('https://growthhub.co.tz',      'GrowthHub',    'hp_demo_growthhub_key_replace_me',  1),
('https://wifi.growthhub.co.tz', 'WiFi Manager', 'hp_demo_wifimanager_key_replace_me', 1);

-- GrowthHub decoys (site_id = 1)
INSERT IGNORE INTO aegis_decoy_users (site_id, fake_username, fake_email, fake_role, fake_created_at) VALUES
(1, 'mmari_admin',      'admin@growthhub.co.tz',        'Administrator', '2025-01-15 09:00:00'),
(1, 'juma.mwangi',      'juma.m@growthhub.co.tz',       'Manager',       '2025-02-03 11:22:00'),
(1, 'client_asha',      'asha.client@gmail.com',         'Client',        '2025-03-10 14:05:00'),
(1, 'finance_beatrice', 'beatrice.f@growthhub.co.tz',   'Finance',       '2025-04-22 08:40:00'),
(1, 'support_neema',    'neema.support@growthhub.co.tz','Support',       '2025-05-01 10:10:00');

-- WiFi Manager decoys (site_id = 2)
INSERT IGNORE INTO aegis_decoy_users (site_id, fake_username, fake_email, fake_role, fake_created_at) VALUES
(2, 'wifi_admin',   'admin@wifi.growthhub.co.tz',  'Administrator', '2025-06-01 08:00:00'),
(2, 'radius_user',  'radius@wifi.growthhub.co.tz', 'Network Admin', '2025-06-15 10:00:00');

-- ============================================================
-- Ghost Tracker IDs
-- Stores forensic breadcrumb IDs planted in decoy responses.
-- If any of these IDs appear in a future request, the attacker
-- is confirmed to be actively using stolen decoy data.
-- ============================================================
CREATE TABLE IF NOT EXISTS aegis_ghost_ids (
    id                    INT          NOT NULL AUTO_INCREMENT,
    ghost_id              VARCHAR(80)  NOT NULL UNIQUE,
    site_id               INT          NOT NULL,
    session_key           VARCHAR(64)  NOT NULL,
    system_type           VARCHAR(40)  NOT NULL,
    context               VARCHAR(60)  NOT NULL DEFAULT 'id',
    triggered             TINYINT(1)   NOT NULL DEFAULT 0,
    triggered_at          TIMESTAMP    NULL,
    triggered_by_session  VARCHAR(64)  NULL,
    triggered_by_ip       VARCHAR(45)  NULL,
    created_at            TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    FOREIGN KEY (site_id) REFERENCES aegis_sites(id) ON DELETE CASCADE,
    INDEX idx_ghost_id    (ghost_id),
    INDEX idx_triggered   (triggered),
    INDEX idx_session     (session_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================
-- Scorched Earth Tripwire log
-- Records every time a sentinel UUID is accessed.
-- ============================================================
CREATE TABLE IF NOT EXISTS aegis_scorched_earth_log (
    id           INT          NOT NULL AUTO_INCREMENT,
    site_id      INT          NOT NULL,
    session_key  VARCHAR(64)  NOT NULL,
    ip_address   VARCHAR(45),
    sentinel_id  VARCHAR(80)  NOT NULL,
    system_type  VARCHAR(40),
    evidence     TEXT,
    triggered_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    FOREIGN KEY (site_id) REFERENCES aegis_sites(id) ON DELETE CASCADE,
    INDEX idx_session (session_key),
    INDEX idx_ip      (ip_address)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================
-- Defense audit log
-- Records which defenses fired for each event.
-- ============================================================
CREATE TABLE IF NOT EXISTS aegis_defense_log (
    id             INT          NOT NULL AUTO_INCREMENT,
    site_id        INT          NOT NULL,
    session_key    VARCHAR(64)  NOT NULL,
    defenses_fired JSON         NOT NULL,
    system_type    VARCHAR(40),
    skill_level    VARCHAR(20),
    phase          VARCHAR(30),
    severity       TINYINT UNSIGNED NOT NULL DEFAULT 0,
    created_at     TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    FOREIGN KEY (site_id) REFERENCES aegis_sites(id) ON DELETE CASCADE,
    INDEX idx_session (session_key),
    INDEX idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
