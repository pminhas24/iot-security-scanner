-- IoT Security Scanner Database Schema (PostgreSQL)
-- For SQLite, the db_manager handles DDL differences automatically.

CREATE TABLE IF NOT EXISTS scans (
    scan_id         SERIAL PRIMARY KEY,
    scan_timestamp  TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    network_range   VARCHAR(50) NOT NULL,
    scan_type       VARCHAR(30) NOT NULL,
    devices_found   INTEGER DEFAULT 0,
    duration_sec    REAL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS devices (
    device_id       SERIAL PRIMARY KEY,
    scan_id         INTEGER NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    ip_address      VARCHAR(45) NOT NULL,
    hostname        VARCHAR(255) DEFAULT '',
    mac_address     VARCHAR(17) DEFAULT '',
    vendor          VARCHAR(255) DEFAULT '',
    state           VARCHAR(20) DEFAULT 'unknown',
    os_guess        VARCHAR(255) DEFAULT '',
    device_type     VARCHAR(50) DEFAULT 'unknown',
    manufacturer    VARCHAR(255) DEFAULT '',
    model           VARCHAR(255) DEFAULT '',
    firmware_version VARCHAR(100) DEFAULT '',
    risk_score      INTEGER DEFAULT 0,
    risk_level      VARCHAR(20) DEFAULT 'low',
    first_seen      TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen       TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(scan_id, ip_address)
);

CREATE TABLE IF NOT EXISTS open_ports (
    port_id         SERIAL PRIMARY KEY,
    device_id       INTEGER NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    port            INTEGER NOT NULL,
    protocol        VARCHAR(10) DEFAULT 'tcp',
    service         VARCHAR(100) DEFAULT 'unknown',
    product         VARCHAR(255) DEFAULT '',
    version         VARCHAR(100) DEFAULT '',
    is_dangerous    BOOLEAN DEFAULT FALSE,
    danger_reason   TEXT DEFAULT '',
    severity        VARCHAR(20) DEFAULT 'info'
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    vuln_id         SERIAL PRIMARY KEY,
    device_id       INTEGER NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    vuln_type       VARCHAR(50) NOT NULL,
    severity        VARCHAR(20) NOT NULL,
    details         TEXT DEFAULT '',
    remediation     TEXT DEFAULT '',
    port            INTEGER,
    discovered_at   TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_devices_scan_id ON devices(scan_id);
CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip_address);
CREATE INDEX IF NOT EXISTS idx_devices_risk ON devices(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_open_ports_device ON open_ports(device_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_device ON vulnerabilities(device_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity);
