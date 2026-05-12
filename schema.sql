CREATE DATABASE IF NOT EXISTS smartzone_portal CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE smartzone_portal;

CREATE TABLE IF NOT EXISTS devices (
    mac                CHAR(12) NOT NULL PRIMARY KEY,         -- canonical: lowercase, no separators
    status             ENUM('pending','approved','denied') NOT NULL DEFAULT 'pending',
    hostname           VARCHAR(255) NULL,
    device_type        VARCHAR(64) NULL,
    friendly_name      VARCHAR(128) NULL,
    note               TEXT NULL,

    requested_by_email VARCHAR(255) NULL,
    requested_by_sub   VARCHAR(64)  NULL,
    requested_at       DATETIME NULL,

    decided_by_email   VARCHAR(255) NULL,
    decided_at         DATETIME NULL,

    first_seen_ssid    VARCHAR(64)  NULL,
    first_seen_ap_mac  CHAR(17)     NULL,
    last_seen_at       DATETIME NULL,

    INDEX idx_status (status),
    INDEX idx_requested_by (requested_by_email)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS audit_log (
    id          BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    ts          DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    actor_email VARCHAR(255) NULL,
    action      VARCHAR(32)  NOT NULL,    -- e.g. radius_reject, radius_accept, request, approve, deny, coa_sent
    mac         CHAR(12)     NULL,
    details     TEXT         NULL,
    INDEX idx_ts (ts),
    INDEX idx_mac (mac)
) ENGINE=InnoDB;
