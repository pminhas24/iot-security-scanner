#!/usr/bin/env python
"""
dev_run.py — Run the IoT Scanner dashboard locally without Docker or Nmap.

Seeds a local SQLite database with realistic demo IoT devices so the full
dashboard (risk counts, device table, detail pages, settings panel) can be
used and tested immediately.

Usage:
    python dev_run.py                 # Seed demo data and start dashboard
    python dev_run.py --port 8080     # Use a different port
    python dev_run.py --reseed        # Drop and recreate demo data, then start
    python dev_run.py --no-seed       # Start with whatever data is already in DB
    python dev_run.py --test          # Run the test suite and exit
    python dev_run.py --test -v       # Run tests with verbose output
"""

import argparse
import os
import sqlite3
import subprocess
import sys

# Make src/ importable without setting PYTHONPATH in the shell
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

DEMO_DB = os.path.join(os.path.dirname(__file__), "demo.db")

# ---------------------------------------------------------------------------
# Schema (mirrors DatabaseManager.SQLITE_SCHEMA)
# ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_timestamp  TEXT DEFAULT (datetime('now')),
    network_range   TEXT NOT NULL,
    scan_type       TEXT NOT NULL,
    devices_found   INTEGER DEFAULT 0,
    duration_sec    REAL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS devices (
    device_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id         INTEGER NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    ip_address      TEXT NOT NULL,
    hostname        TEXT DEFAULT '',
    mac_address     TEXT DEFAULT '',
    vendor          TEXT DEFAULT '',
    state           TEXT DEFAULT 'unknown',
    os_guess        TEXT DEFAULT '',
    device_type     TEXT DEFAULT 'unknown',
    manufacturer    TEXT DEFAULT '',
    model           TEXT DEFAULT '',
    firmware_version TEXT DEFAULT '',
    risk_score      INTEGER DEFAULT 0,
    risk_level      TEXT DEFAULT 'low',
    first_seen      TEXT DEFAULT (datetime('now')),
    last_seen       TEXT DEFAULT (datetime('now')),
    UNIQUE(scan_id, ip_address)
);

CREATE TABLE IF NOT EXISTS open_ports (
    port_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id       INTEGER NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    port            INTEGER NOT NULL,
    protocol        TEXT DEFAULT 'tcp',
    service         TEXT DEFAULT 'unknown',
    product         TEXT DEFAULT '',
    version         TEXT DEFAULT '',
    is_dangerous    INTEGER DEFAULT 0,
    danger_reason   TEXT DEFAULT '',
    severity        TEXT DEFAULT 'info'
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    vuln_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id       INTEGER NOT NULL REFERENCES devices(device_id) ON DELETE CASCADE,
    vuln_type       TEXT NOT NULL,
    severity        TEXT NOT NULL,
    details         TEXT DEFAULT '',
    remediation     TEXT DEFAULT '',
    port            INTEGER,
    discovered_at   TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_devices_scan_id ON devices(scan_id);
CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip_address);
CREATE INDEX IF NOT EXISTS idx_open_ports_device ON open_ports(device_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_device ON vulnerabilities(device_id);
"""

# ---------------------------------------------------------------------------
# Demo data
# ---------------------------------------------------------------------------

DEMO_DEVICES = [
    {
        "ip": "192.168.1.1",
        "hostname": "router.home",
        "mac": "A4:2B:8C:12:34:56",
        "vendor": "TP-Link",
        "device_type": "router",
        "manufacturer": "TP-Link",
        "model": "Archer AX50",
        "firmware": "1.0.12",
        "risk_score": 88,
        "risk_level": "critical",
        "ports": [
            (80,  "tcp", "http",    "TP-Link HTTP",  "1.0",  0, "",                       "info"),
            (443, "tcp", "https",   "TP-Link HTTPS", "1.0",  0, "",                       "info"),
            (22,  "tcp", "ssh",     "OpenSSH",       "7.2",  0, "",                       "info"),
            (23,  "tcp", "telnet",  "BusyBox",       "1.29", 1, "Unencrypted admin shell", "critical"),
        ],
        "vulns": [
            ("default_credentials", "critical",
             "Default admin:admin credentials accepted on the web interface (port 80).",
             "Change the default password immediately in the router admin panel.", 80),
            ("telnet_exposed", "high",
             "Telnet service active on port 23 — all traffic transmitted in plain text.",
             "Disable Telnet in router settings and use SSH instead.", 23),
        ],
    },
    {
        "ip": "192.168.1.42",
        "hostname": "ipcam-front-door",
        "mac": "B8:27:EB:AA:BB:CC",
        "vendor": "Hikvision",
        "device_type": "camera",
        "manufacturer": "Hikvision",
        "model": "DS-2CD2143G2-I",
        "firmware": "5.6.3",
        "risk_score": 72,
        "risk_level": "high",
        "ports": [
            (80,   "tcp", "http",   "Hikvision DVR", "",    1, "Unencrypted camera stream", "high"),
            (554,  "tcp", "rtsp",   "RTSP",          "",    1, "RTSP stream unauthenticated", "high"),
            (8000, "tcp", "sdk",    "Hikvision SDK", "",    0, "",                            "info"),
        ],
        "vulns": [
            ("unencrypted_stream", "high",
             "Camera video stream accessible over HTTP without authentication (port 80).",
             "Enable HTTPS and require login to access the camera feed.", 80),
            ("rtsp_no_auth", "medium",
             "RTSP stream on port 554 accepts connections without credentials.",
             "Set an RTSP username and password in the camera settings.", 554),
        ],
    },
    {
        "ip": "192.168.1.55",
        "hostname": "samsung-tv",
        "mac": "C0:4A:00:11:22:33",
        "vendor": "Samsung",
        "device_type": "media_player",
        "manufacturer": "Samsung",
        "model": "QN85Q80C",
        "firmware": "1440.3",
        "risk_score": 45,
        "risk_level": "medium",
        "ports": [
            (1900, "tcp", "upnp",  "UPnP/DLNA",    "",    1, "UPnP device discovery exposed", "medium"),
            (7676, "tcp", "dlna",  "DLNA Media",   "",    0, "",                               "info"),
            (8080, "tcp", "http",  "Tizen HTTP",   "",    0, "",                               "info"),
        ],
        "vulns": [
            ("upnp_exposed", "medium",
             "UPnP/DLNA service reachable from the local network — can expose device info.",
             "Disable UPnP in the TV network settings if DLNA casting is not needed.", 1900),
            ("outdated_firmware", "low",
             "Firmware version 1440.3 is more than 18 months old.",
             "Check for firmware updates in the TV system settings.", None),
        ],
    },
    {
        "ip": "192.168.1.78",
        "hostname": "hp-laserjet",
        "mac": "D4:6A:91:AA:BB:EE",
        "vendor": "Hewlett-Packard",
        "device_type": "printer",
        "manufacturer": "HP",
        "model": "LaserJet Pro M404dn",
        "firmware": "002.1748A",
        "risk_score": 38,
        "risk_level": "medium",
        "ports": [
            (9100, "tcp", "raw",   "JetDirect",    "",    1, "Raw print port exposed", "medium"),
            (80,   "tcp", "http",  "HP EWS",       "",    0, "",                       "info"),
            (443,  "tcp", "https", "HP EWS HTTPS", "",    0, "",                       "info"),
            (631,  "tcp", "ipp",   "CUPS IPP",     "2.3", 0, "",                       "info"),
        ],
        "vulns": [
            ("raw_print_exposed", "medium",
             "JetDirect port 9100 accepts raw print jobs without authentication.",
             "Restrict port 9100 in the printer firewall or block it at the router.", 9100),
        ],
    },
    {
        "ip": "192.168.1.101",
        "hostname": "macbook-pro",
        "mac": "F0:18:98:55:66:77",
        "vendor": "Apple",
        "device_type": "computer",
        "manufacturer": "Apple",
        "model": "MacBook Pro (2023)",
        "firmware": "",
        "risk_score": 8,
        "risk_level": "low",
        "ports": [
            (5000, "tcp", "http", "AirPlay",  "",    0, "", "info"),
            (7000, "tcp", "rtsp", "AirPlay",  "",    0, "", "info"),
        ],
        "vulns": [],
    },
    {
        "ip": "192.168.1.120",
        "hostname": "nest-thermostat",
        "mac": "18:B4:30:99:AA:BB",
        "vendor": "Google",
        "device_type": "smart_appliance",
        "manufacturer": "Google",
        "model": "Nest Learning Thermostat (4th Gen)",
        "firmware": "6.9.6",
        "risk_score": 15,
        "risk_level": "low",
        "ports": [
            (443, "tcp", "https", "Nest HTTPS", "TLS 1.3", 0, "", "info"),
        ],
        "vulns": [],
    },
]


# ---------------------------------------------------------------------------
# Seed logic
# ---------------------------------------------------------------------------

def seed_demo_data(db_path: str, reseed: bool = False) -> None:
    """Create schema and insert demo devices. Skips if data already exists."""
    if reseed and os.path.exists(db_path):
        os.remove(db_path)
        print(f"  Removed existing DB: {db_path}")

    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA)

    cursor = conn.cursor()

    # Skip if data already seeded
    cursor.execute("SELECT COUNT(*) FROM scans")
    if cursor.fetchone()[0] > 0 and not reseed:
        print(f"  Demo data already present in {db_path} — skipping seed.")
        conn.close()
        return

    # Insert a scan
    cursor.execute(
        "INSERT INTO scans (network_range, scan_type, devices_found, duration_sec, scan_timestamp) "
        "VALUES (?, ?, ?, ?, datetime('now'))",
        ("192.168.1.0/24", "full", len(DEMO_DEVICES), 41.7),
    )
    scan_id = cursor.lastrowid

    for d in DEMO_DEVICES:
        cursor.execute(
            """INSERT INTO devices
               (scan_id, ip_address, hostname, mac_address, vendor, state,
                device_type, manufacturer, model, firmware_version,
                risk_score, risk_level)
               VALUES (?, ?, ?, ?, ?, 'up', ?, ?, ?, ?, ?, ?)""",
            (scan_id, d["ip"], d["hostname"], d["mac"], d["vendor"],
             d["device_type"], d["manufacturer"], d["model"], d["firmware"],
             d["risk_score"], d["risk_level"]),
        )
        device_id = cursor.lastrowid

        for port in d["ports"]:
            cursor.execute(
                """INSERT INTO open_ports
                   (device_id, port, protocol, service, product, version,
                    is_dangerous, danger_reason, severity)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (device_id, *port),
            )

        for vuln in d["vulns"]:
            cursor.execute(
                """INSERT INTO vulnerabilities
                   (device_id, vuln_type, severity, details, remediation, port)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (device_id, *vuln),
            )

    conn.commit()
    conn.close()
    print(f"  Seeded {len(DEMO_DEVICES)} demo devices into {db_path}")


# ---------------------------------------------------------------------------
# Run modes
# ---------------------------------------------------------------------------

def run_server(db_path: str, port: int, debug: bool) -> None:
    from api.app import create_app

    app = create_app({"db_type": "sqlite", "db_path": db_path})
    print(f"\n  Open http://localhost:{port}/ in your browser")
    print("  Press Ctrl+C to stop\n")
    app.run(host="0.0.0.0", port=port, debug=debug, use_reloader=False)


def run_tests(extra_args: list) -> None:
    env = {**os.environ, "PYTHONPATH": os.path.join(os.path.dirname(__file__), "src")}
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/"] + extra_args,
        env=env,
    )
    sys.exit(result.returncode)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run IoT Scanner dashboard locally with demo data",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--port", type=int, default=5000, help="HTTP port (default: 5000)")
    parser.add_argument("--db", default=DEMO_DB, help="SQLite database path")
    parser.add_argument("--reseed", action="store_true", help="Drop and recreate demo data")
    parser.add_argument("--no-seed", action="store_true", help="Skip seeding — use existing DB")
    parser.add_argument("--debug", action="store_true", help="Enable Flask debug mode")
    parser.add_argument("--test", action="store_true", help="Run test suite instead of server")
    args, remaining = parser.parse_known_args()

    if args.test:
        print("Running test suite...\n")
        run_tests(remaining)
        return

    print("\nIoT Scanner — local dev mode")
    print("=" * 40)

    if not args.no_seed:
        seed_demo_data(args.db, reseed=args.reseed)

    run_server(args.db, args.port, args.debug)


if __name__ == "__main__":
    main()
