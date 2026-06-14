"""
Database Manager for IoT Security Scanner.

Provides CRUD operations for storing scan results. Supports both
SQLite (default, zero-config) and PostgreSQL backends.
"""

import logging
import os
import sqlite3
from typing import Optional

from scanner.models import DeviceScanResult

logger = logging.getLogger(__name__)


class DatabaseError(Exception):
    """Raised when a database operation fails."""
    pass


class DatabaseManager:
    """
    Manages database operations for scan results.

    Supports dual backends:
    - SQLite (default): Zero setup, stores to a local file.
    - PostgreSQL: Production-ready, requires a running server.

    Usage:
        with DatabaseManager(db_type="sqlite", db_path="scanner.db") as db:
            db.initialize_schema()
            db.save_scan("192.168.1.0/24", "full", results)
    """

    # SQLite schema (differs from PostgreSQL in auto-increment syntax)
    SQLITE_SCHEMA = """
    CREATE TABLE IF NOT EXISTS scans (
        scan_id         INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_timestamp  TEXT DEFAULT (datetime('now')),
        network_range   TEXT NOT NULL,
        scan_type       TEXT NOT NULL,
        devices_found   INTEGER DEFAULT 0,
        duration_sec    REAL DEFAULT 0,
        status          TEXT DEFAULT 'completed',
        progress        TEXT DEFAULT '',
        started_at      TEXT DEFAULT (datetime('now')),
        finished_at     TEXT
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
    CREATE INDEX IF NOT EXISTS idx_devices_risk ON devices(risk_score DESC);
    CREATE INDEX IF NOT EXISTS idx_open_ports_device ON open_ports(device_id);
    CREATE INDEX IF NOT EXISTS idx_vulnerabilities_device ON vulnerabilities(device_id);
    CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity);
    """

    def __init__(
        self,
        db_type: str = "sqlite",
        db_path: str = "iot_scanner.db",
        host: str = "localhost",
        port: int = 5432,
        database: str = "iot_scanner",
        user: str = "iot_scanner",
        password: str = "",
    ):
        """
        Initialize the DatabaseManager.

        Args:
            db_type: "sqlite" or "postgresql".
            db_path: Path for SQLite database file.
            host: PostgreSQL host.
            port: PostgreSQL port.
            database: PostgreSQL database name.
            user: PostgreSQL user.
            password: PostgreSQL password.
        """
        self.db_type = db_type.lower()
        self.db_path = db_path
        self.pg_params = {
            "host": host,
            "port": port,
            "database": database,
            "user": user,
            "password": password,
        }
        self._conn = None

    def connect(self) -> None:
        """Establish database connection."""
        try:
            if self.db_type == "sqlite":
                self._conn = sqlite3.connect(self.db_path)
                self._conn.execute("PRAGMA foreign_keys = ON")
                self._conn.execute("PRAGMA journal_mode = WAL")
                self._conn.row_factory = sqlite3.Row
                logger.info(f"Connected to SQLite database: {self.db_path}")
            elif self.db_type == "postgresql":
                import psycopg2
                import psycopg2.extras
                self._conn = psycopg2.connect(**self.pg_params)
                self._conn.autocommit = False
                logger.info(
                    f"Connected to PostgreSQL: "
                    f"{self.pg_params['host']}:{self.pg_params['port']}/"
                    f"{self.pg_params['database']}"
                )
            else:
                raise DatabaseError(f"Unsupported database type: {self.db_type}")
        except Exception as e:
            raise DatabaseError(f"Failed to connect to database: {e}")

    def disconnect(self) -> None:
        """Close database connection."""
        if self._conn:
            try:
                self._conn.close()
                logger.debug("Database connection closed")
            except Exception as e:
                logger.warning(f"Error closing database connection: {e}")
            finally:
                self._conn = None

    def initialize_schema(self) -> None:
        """
        Create database tables if they don't exist.

        Uses the appropriate schema for the current backend.
        """
        if self._conn is None:
            raise DatabaseError("Not connected to database")

        try:
            cursor = self._conn.cursor()
            if self.db_type == "sqlite":
                cursor.executescript(self.SQLITE_SCHEMA)
            else:
                # PostgreSQL: read from schema.sql
                schema_path = os.path.join(
                    os.path.dirname(__file__), "schema.sql"
                )
                with open(schema_path) as f:
                    cursor.execute(f.read())
                self._conn.commit()
            logger.info("Database schema initialized")
        except Exception as e:
            if self.db_type == "postgresql" and self._conn:
                self._conn.rollback()
            raise DatabaseError(f"Failed to initialize schema: {e}")

    def save_scan(
        self,
        network_range: str,
        scan_type: str,
        results: list[DeviceScanResult],
        duration_sec: float = 0,
    ) -> int:
        """
        Save a complete scan session with all device data.

        Creates rows in scans, devices, open_ports, and vulnerabilities.

        Args:
            network_range: The scanned network range.
            scan_type: Scan type ('discovery', 'quick', 'full', 'targeted').
            results: List of DeviceScanResult objects.
            duration_sec: Scan duration in seconds.

        Returns:
            scan_id of the created scan record.

        Raises:
            DatabaseError: If save fails.
        """
        if self._conn is None:
            raise DatabaseError("Not connected to database")

        try:
            cursor = self._conn.cursor()

            # Insert scan record
            if self.db_type == "sqlite":
                cursor.execute(
                    """INSERT INTO scans (network_range, scan_type,
                       devices_found, duration_sec)
                       VALUES (?, ?, ?, ?)""",
                    (network_range, scan_type, len(results), duration_sec),
                )
                scan_id = cursor.lastrowid
            else:
                cursor.execute(
                    """INSERT INTO scans (network_range, scan_type,
                       devices_found, duration_sec)
                       VALUES (%s, %s, %s, %s) RETURNING scan_id""",
                    (network_range, scan_type, len(results), duration_sec),
                )
                scan_id = cursor.fetchone()[0]

            # Insert each device and its related data
            self._insert_results(cursor, scan_id, results)

            self._conn.commit()
            logger.info(
                f"Saved scan {scan_id}: {len(results)} devices, "
                f"range={network_range}, type={scan_type}"
            )
            return scan_id

        except Exception as e:
            if self._conn:
                self._conn.rollback()
            raise DatabaseError(f"Failed to save scan: {e}")

    def _insert_results(
        self, cursor, scan_id: int, results: list[DeviceScanResult]
    ) -> None:
        """Insert devices, ports, and vulnerabilities for a scan_id.

        Shared by save_scan (legacy one-shot path) and complete_scan
        (live web flow, where the scan row already exists).
        """
        for result in results:
            device_id = self._insert_device(cursor, scan_id, result)
            if device_id:
                self._insert_ports(cursor, device_id, result)
                self._insert_vulnerabilities(cursor, device_id, result)

    # -------------------------------------------------------------------
    # Scan state lifecycle (DB-backed; survives across Gunicorn workers)
    # -------------------------------------------------------------------

    def create_scan(
        self,
        network_range: str,
        scan_type: str,
        progress: str = "Starting scan...",
    ) -> int:
        """
        Create a new scan row marked as running.

        Used by the web flow at scan start so that "is a scan running?"
        and live progress can be read by any worker from the database.

        Args:
            network_range: Target network range (may be a placeholder like
                "auto-detect" that complete_scan later overwrites).
            scan_type: Scan type ('discovery', 'quick', 'full', 'targeted').
            progress: Initial progress message.

        Returns:
            scan_id of the created scan record.
        """
        if self._conn is None:
            raise DatabaseError("Not connected to database")

        try:
            cursor = self._conn.cursor()
            if self.db_type == "sqlite":
                cursor.execute(
                    """INSERT INTO scans (network_range, scan_type, status,
                       progress, started_at)
                       VALUES (?, ?, 'running', ?, datetime('now'))""",
                    (network_range, scan_type, progress),
                )
                scan_id = cursor.lastrowid
            else:
                cursor.execute(
                    """INSERT INTO scans (network_range, scan_type, status,
                       progress, started_at)
                       VALUES (%s, %s, 'running', %s, NOW())
                       RETURNING scan_id""",
                    (network_range, scan_type, progress),
                )
                scan_id = cursor.fetchone()[0]
            self._conn.commit()
            logger.info(f"Created running scan {scan_id} ({network_range})")
            return scan_id
        except Exception as e:
            if self._conn:
                self._conn.rollback()
            raise DatabaseError(f"Failed to create scan: {e}")

    def update_scan_progress(self, scan_id: int, progress: str) -> None:
        """Update the progress message of a running scan."""
        if self._conn is None:
            raise DatabaseError("Not connected to database")

        placeholder = "?" if self.db_type == "sqlite" else "%s"
        try:
            cursor = self._conn.cursor()
            cursor.execute(
                f"UPDATE scans SET progress = {placeholder} "
                f"WHERE scan_id = {placeholder}",
                (progress, scan_id),
            )
            self._conn.commit()
        except Exception as e:
            if self._conn:
                self._conn.rollback()
            raise DatabaseError(f"Failed to update scan progress: {e}")

    def complete_scan(
        self,
        scan_id: int,
        results: list[DeviceScanResult],
        duration_sec: float = 0,
        network_range: Optional[str] = None,
    ) -> None:
        """
        Finalize a running scan: persist devices and mark it completed.

        Inserts devices/ports/vulnerabilities under the existing scan_id
        (no new scan row) and updates the row's status, counts, and timing.

        Args:
            scan_id: The running scan's id (from create_scan).
            results: Device scan results to persist.
            duration_sec: Total scan duration.
            network_range: If given, overwrites the stored range (the web
                flow stores a placeholder at create time and fills the real
                auto-detected subnet here).
        """
        if self._conn is None:
            raise DatabaseError("Not connected to database")

        progress = f"Complete: {len(results)} devices scanned"
        try:
            cursor = self._conn.cursor()
            self._insert_results(cursor, scan_id, results)

            if self.db_type == "sqlite":
                cursor.execute(
                    """UPDATE scans
                       SET status = 'completed', devices_found = ?,
                           duration_sec = ?, progress = ?,
                           finished_at = datetime('now'),
                           network_range = COALESCE(?, network_range)
                       WHERE scan_id = ?""",
                    (len(results), duration_sec, progress,
                     network_range, scan_id),
                )
            else:
                cursor.execute(
                    """UPDATE scans
                       SET status = 'completed', devices_found = %s,
                           duration_sec = %s, progress = %s,
                           finished_at = NOW(),
                           network_range = COALESCE(%s, network_range)
                       WHERE scan_id = %s""",
                    (len(results), duration_sec, progress,
                     network_range, scan_id),
                )
            self._conn.commit()
            logger.info(
                f"Completed scan {scan_id}: {len(results)} devices, "
                f"{duration_sec:.1f}s"
            )
        except Exception as e:
            if self._conn:
                self._conn.rollback()
            raise DatabaseError(f"Failed to complete scan: {e}")

    def fail_scan(self, scan_id: int, error_msg: str) -> None:
        """Mark a running scan as failed with an error message."""
        if self._conn is None:
            raise DatabaseError("Not connected to database")

        progress = f"Error: {error_msg}"
        placeholder = "?" if self.db_type == "sqlite" else "%s"
        now = "datetime('now')" if self.db_type == "sqlite" else "NOW()"
        try:
            cursor = self._conn.cursor()
            cursor.execute(
                f"""UPDATE scans
                    SET status = 'failed', progress = {placeholder},
                        finished_at = {now}
                    WHERE scan_id = {placeholder}""",
                (progress, scan_id),
            )
            self._conn.commit()
            logger.warning(f"Scan {scan_id} failed: {error_msg}")
        except Exception as e:
            if self._conn:
                self._conn.rollback()
            raise DatabaseError(f"Failed to mark scan failed: {e}")

    def get_active_scan(self) -> Optional[dict]:
        """
        Return the most recent running scan, or None.

        Used by the scan-start endpoint to reject concurrent scans.
        """
        if self._conn is None:
            raise DatabaseError("Not connected to database")

        try:
            cursor = self._conn.cursor()
            cursor.execute(
                "SELECT * FROM scans WHERE status = 'running' "
                "ORDER BY scan_id DESC LIMIT 1"
            )
            row = cursor.fetchone()
        except Exception:
            # Table may not exist yet on a brand-new database.
            return None
        if not row:
            return None
        return dict(row) if self.db_type == "sqlite" \
            else self._pg_row_to_dict(row, cursor)

    def get_scan_state(self, scan_id: Optional[int] = None) -> dict:
        """
        Return the live scan state for the status endpoint and SSE stream.

        Defaults to the most recent scan. Defensive: returns an idle state
        if the scans table does not exist yet (fresh database), so status
        reads never 500.

        Returns a dict with keys: running, status, progress, scan_id,
        network_range, started_at, finished_at, last_scan_id.
        """
        idle = {
            "running": False,
            "status": "idle",
            "progress": "",
            "scan_id": None,
            "network_range": None,
            "started_at": None,
            "finished_at": None,
            "last_scan_id": None,
        }
        if self._conn is None:
            raise DatabaseError("Not connected to database")

        placeholder = "?" if self.db_type == "sqlite" else "%s"
        try:
            cursor = self._conn.cursor()
            if scan_id is None:
                cursor.execute(
                    "SELECT * FROM scans ORDER BY scan_id DESC LIMIT 1"
                )
            else:
                cursor.execute(
                    f"SELECT * FROM scans WHERE scan_id = {placeholder}",
                    (scan_id,),
                )
            row = cursor.fetchone()

            if not row:
                return idle

            scan = dict(row) if self.db_type == "sqlite" \
                else self._pg_row_to_dict(row, cursor)

            # Most recent successfully completed scan (for the dashboard).
            cursor.execute(
                "SELECT MAX(scan_id) FROM scans WHERE status = 'completed'"
            )
            last_row = cursor.fetchone()
            last_scan_id = last_row[0] if last_row else None
        except Exception as e:
            logger.debug(f"get_scan_state falling back to idle: {e}")
            return idle

        return {
            "running": scan["status"] == "running",
            "status": scan["status"],
            "progress": scan["progress"] or "",
            "scan_id": scan["scan_id"],
            "network_range": scan["network_range"],
            "started_at": scan["started_at"],
            "finished_at": scan["finished_at"],
            "last_scan_id": last_scan_id,
        }

    def _insert_device(
        self, cursor, scan_id: int, result: DeviceScanResult
    ) -> Optional[int]:
        """Insert a device record and return device_id."""
        d = result.device
        fp = result.fingerprint
        vr = result.vulnerability_report

        params = (
            scan_id,
            d.ip_address,
            d.hostname or "",
            d.mac_address or "",
            d.vendor or "",
            d.state or "unknown",
            d.os_guess or "",
            fp.device_type if fp else "unknown",
            fp.manufacturer if fp else (d.vendor or ""),
            fp.model if fp else "",
            fp.firmware_version if fp else "",
            vr.risk_score if vr else 0,
            vr.risk_level if vr else "low",
        )

        if self.db_type == "sqlite":
            cursor.execute(
                """INSERT INTO devices (scan_id, ip_address, hostname,
                   mac_address, vendor, state, os_guess, device_type,
                   manufacturer, model, firmware_version, risk_score,
                   risk_level)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                params,
            )
            return cursor.lastrowid
        else:
            cursor.execute(
                """INSERT INTO devices (scan_id, ip_address, hostname,
                   mac_address, vendor, state, os_guess, device_type,
                   manufacturer, model, firmware_version, risk_score,
                   risk_level)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                   RETURNING device_id""",
                params,
            )
            return cursor.fetchone()[0]

    def _insert_ports(
        self, cursor, device_id: int, result: DeviceScanResult
    ) -> None:
        """Insert open port records for a device."""
        if not result.port_scan:
            return

        for p in result.port_scan.open_ports:
            params = (
                device_id,
                p.port,
                p.protocol,
                p.service,
                p.product,
                p.version,
                1 if p.is_dangerous else 0,
                p.danger_reason,
                p.severity.value,
            )
            placeholder = "?" if self.db_type == "sqlite" else "%s"
            cursor.execute(
                f"""INSERT INTO open_ports (device_id, port, protocol,
                    service, product, version, is_dangerous,
                    danger_reason, severity)
                    VALUES ({', '.join([placeholder] * 9)})""",
                params,
            )

    def _insert_vulnerabilities(
        self, cursor, device_id: int, result: DeviceScanResult
    ) -> None:
        """Insert vulnerability records for a device."""
        if not result.vulnerability_report:
            return

        for v in result.vulnerability_report.vulnerabilities:
            params = (
                device_id,
                v.vuln_type,
                v.severity.value,
                v.details,
                v.remediation,
                v.port,
            )
            placeholder = "?" if self.db_type == "sqlite" else "%s"
            cursor.execute(
                f"""INSERT INTO vulnerabilities (device_id, vuln_type,
                    severity, details, remediation, port)
                    VALUES ({', '.join([placeholder] * 6)})""",
                params,
            )

    # -------------------------------------------------------------------
    # Query Methods
    # -------------------------------------------------------------------

    def get_all_devices(self, scan_id: Optional[int] = None) -> list[dict]:
        """
        Retrieve all devices, optionally filtered by scan_id.

        If no scan_id is given, returns devices from the most recent scan.

        Args:
            scan_id: Optional scan ID to filter by.

        Returns:
            List of device dicts with nested ports and vulnerabilities.
        """
        if self._conn is None:
            raise DatabaseError("Not connected to database")

        cursor = self._conn.cursor()

        if scan_id is None:
            # Get most recent scan
            cursor.execute(
                "SELECT MAX(scan_id) FROM scans"
            )
            row = cursor.fetchone()
            scan_id = row[0] if row and row[0] else None
            if scan_id is None:
                return []

        placeholder = "?" if self.db_type == "sqlite" else "%s"
        cursor.execute(
            f"SELECT * FROM devices WHERE scan_id = {placeholder} "
            f"ORDER BY risk_score DESC",
            (scan_id,),
        )

        devices = []
        for row in cursor.fetchall():
            device = dict(row) if self.db_type == "sqlite" else self._pg_row_to_dict(row, cursor)
            device_id = device["device_id"]

            # Get ports
            cursor.execute(
                f"SELECT * FROM open_ports WHERE device_id = {placeholder}",
                (device_id,),
            )
            device["ports"] = [
                dict(r) if self.db_type == "sqlite" else self._pg_row_to_dict(r, cursor)
                for r in cursor.fetchall()
            ]

            # Get vulnerabilities
            cursor.execute(
                f"SELECT * FROM vulnerabilities WHERE device_id = {placeholder}",
                (device_id,),
            )
            device["vulnerabilities"] = [
                dict(r) if self.db_type == "sqlite" else self._pg_row_to_dict(r, cursor)
                for r in cursor.fetchall()
            ]

            devices.append(device)

        return devices

    def get_device_by_ip(self, ip_address: str) -> Optional[dict]:
        """
        Get the most recent record for a specific IP address.

        Args:
            ip_address: IP address to look up.

        Returns:
            Device dict with ports and vulnerabilities, or None.
        """
        if self._conn is None:
            raise DatabaseError("Not connected to database")

        cursor = self._conn.cursor()
        placeholder = "?" if self.db_type == "sqlite" else "%s"

        cursor.execute(
            f"""SELECT d.* FROM devices d
                JOIN scans s ON d.scan_id = s.scan_id
                WHERE d.ip_address = {placeholder}
                ORDER BY s.scan_timestamp DESC LIMIT 1""",
            (ip_address,),
        )
        row = cursor.fetchone()
        if not row:
            return None

        device = dict(row) if self.db_type == "sqlite" else self._pg_row_to_dict(row, cursor)
        device_id = device["device_id"]

        cursor.execute(
            f"SELECT * FROM open_ports WHERE device_id = {placeholder}",
            (device_id,),
        )
        device["ports"] = [
            dict(r) if self.db_type == "sqlite" else self._pg_row_to_dict(r, cursor)
            for r in cursor.fetchall()
        ]

        cursor.execute(
            f"SELECT * FROM vulnerabilities WHERE device_id = {placeholder}",
            (device_id,),
        )
        device["vulnerabilities"] = [
            dict(r) if self.db_type == "sqlite" else self._pg_row_to_dict(r, cursor)
            for r in cursor.fetchall()
        ]

        return device

    def get_vulnerabilities(
        self,
        severity: Optional[str] = None,
        device_id: Optional[int] = None,
    ) -> list[dict]:
        """
        Get vulnerabilities with optional filters.

        Args:
            severity: Filter by severity level.
            device_id: Filter by device.

        Returns:
            List of vulnerability dicts with device IP included.
        """
        if self._conn is None:
            raise DatabaseError("Not connected to database")

        cursor = self._conn.cursor()
        placeholder = "?" if self.db_type == "sqlite" else "%s"

        query = """
            SELECT v.*, d.ip_address, d.hostname, d.device_type
            FROM vulnerabilities v
            JOIN devices d ON v.device_id = d.device_id
            WHERE 1=1
        """
        params: list = []

        if severity:
            query += f" AND v.severity = {placeholder}"
            params.append(severity)
        if device_id:
            query += f" AND v.device_id = {placeholder}"
            params.append(device_id)

        query += " ORDER BY v.severity, d.ip_address"

        cursor.execute(query, params)
        return [
            dict(r) if self.db_type == "sqlite" else self._pg_row_to_dict(r, cursor)
            for r in cursor.fetchall()
        ]

    def get_scan_history(self, limit: int = 20) -> list[dict]:
        """
        Get recent scan records.

        Args:
            limit: Maximum number of scans to return.

        Returns:
            List of scan dicts.
        """
        if self._conn is None:
            raise DatabaseError("Not connected to database")

        cursor = self._conn.cursor()
        placeholder = "?" if self.db_type == "sqlite" else "%s"

        cursor.execute(
            f"SELECT * FROM scans ORDER BY scan_timestamp DESC LIMIT {placeholder}",
            (limit,),
        )
        return [
            dict(r) if self.db_type == "sqlite" else self._pg_row_to_dict(r, cursor)
            for r in cursor.fetchall()
        ]

    def get_risk_summary(self) -> dict:
        """
        Aggregate risk statistics for the most recent scan.

        Returns:
            Dict with total_devices, critical, high, medium, low counts,
            avg_risk_score, and most_vulnerable_device info.
        """
        if self._conn is None:
            raise DatabaseError("Not connected to database")

        cursor = self._conn.cursor()

        # Get most recent scan_id
        cursor.execute("SELECT MAX(scan_id) FROM scans")
        row = cursor.fetchone()
        scan_id = row[0] if row and row[0] else None
        if scan_id is None:
            return {
                "total_devices": 0, "critical": 0, "high": 0,
                "medium": 0, "low": 0, "avg_risk_score": 0,
                "most_vulnerable": None,
            }

        placeholder = "?" if self.db_type == "sqlite" else "%s"

        # Count by risk level
        cursor.execute(
            f"""SELECT risk_level, COUNT(*) as cnt
                FROM devices WHERE scan_id = {placeholder}
                GROUP BY risk_level""",
            (scan_id,),
        )
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for row in cursor.fetchall():
            level = row[0] if self.db_type != "sqlite" else row["risk_level"]
            count = row[1] if self.db_type != "sqlite" else row["cnt"]
            if level in counts:
                counts[level] = count

        # Get average risk score
        cursor.execute(
            f"""SELECT COUNT(*), AVG(risk_score)
                FROM devices WHERE scan_id = {placeholder}""",
            (scan_id,),
        )
        row = cursor.fetchone()
        total = row[0] if row else 0
        avg_score = round(row[1] or 0, 1) if row else 0

        # Get most vulnerable device
        cursor.execute(
            f"""SELECT ip_address, hostname, risk_score, risk_level
                FROM devices WHERE scan_id = {placeholder}
                ORDER BY risk_score DESC LIMIT 1""",
            (scan_id,),
        )
        row = cursor.fetchone()
        most_vuln = None
        if row:
            if self.db_type == "sqlite":
                most_vuln = dict(row)
            else:
                most_vuln = self._pg_row_to_dict(row, cursor)

        return {
            "total_devices": total,
            "critical": counts["critical"],
            "high": counts["high"],
            "medium": counts["medium"],
            "low": counts["low"],
            "avg_risk_score": avg_score,
            "most_vulnerable": most_vuln,
        }

    # -------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------

    @staticmethod
    def _pg_row_to_dict(row, cursor) -> dict:
        """Convert a psycopg2 row to a dict using cursor.description."""
        if row is None:
            return {}
        columns = [desc[0] for desc in cursor.description]
        return dict(zip(columns, row))

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()
