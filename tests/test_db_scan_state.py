"""
Tests for database-backed scan state (Phase 1: scan state in DB).

Scan lifecycle state (running / progress / completed / failed) must live in
the `scans` table so it survives across Gunicorn workers, instead of in the
single-process app.config["SCAN_STATUS"] dict. These tests drive the new CRUD
functions on DatabaseManager.

A lightweight 'scanner' package stub is registered before importing
db_manager so we don't drag in the whole scanner runtime (paramiko/scapy)
just to exercise SQLite CRUD — db_manager only needs scanner.models, which is
stdlib-only.
"""

import os
import sys
import types

REPO_ROOT = os.path.join(os.path.dirname(__file__), '..')
SRC = os.path.join(REPO_ROOT, 'src')
sys.path.insert(0, SRC)

if 'scanner' not in sys.modules:
    _pkg = types.ModuleType('scanner')
    _pkg.__path__ = [os.path.join(SRC, 'scanner')]
    sys.modules['scanner'] = _pkg

import pytest  # noqa: E402

from database.db_manager import DatabaseManager  # noqa: E402
from scanner.models import (  # noqa: E402
    DeviceScanResult,
    DeviceFingerprint,
    VulnerabilityReport,
    VulnerabilityDetail,
    PortScanResult,
    PortInfo,
    Severity,
)
from scanner.network_discovery import DiscoveredDevice  # noqa: E402


@pytest.fixture
def db(tmp_path):
    """A connected, schema-initialized SQLite DB on a real file.

    A file (not :memory:) is used because scan-state sharing across
    connections is the whole point — :memory: gives each connection its
    own database.
    """
    manager = DatabaseManager(
        db_type="sqlite", db_path=str(tmp_path / "scan_state.db")
    )
    manager.connect()
    manager.initialize_schema()
    yield manager
    manager.disconnect()


def _make_result(ip="192.168.1.10", risk_score=42, risk_level="medium"):
    """Build a minimal but complete DeviceScanResult for save/complete tests."""
    return DeviceScanResult(
        device=DiscoveredDevice(ip_address=ip, hostname="dev", vendor="Acme"),
        port_scan=PortScanResult(
            ip_address=ip,
            open_ports=[PortInfo(port=80, service="http")],
        ),
        fingerprint=DeviceFingerprint(
            ip_address=ip, device_type="router", manufacturer="Acme"
        ),
        vulnerability_report=VulnerabilityReport(
            ip_address=ip,
            risk_score=risk_score,
            risk_level=risk_level,
            vulnerabilities=[
                VulnerabilityDetail(
                    vuln_type="default_credentials",
                    severity=Severity.HIGH,
                    details="x",
                ),
            ],
        ),
    )


# --- create_scan / get_active_scan ----------------------------------------

def test_create_scan_returns_id_and_marks_running(db):
    scan_id = db.create_scan("192.168.1.0/24", "full")
    assert isinstance(scan_id, int)

    active = db.get_active_scan()
    assert active is not None
    assert active["scan_id"] == scan_id
    assert active["status"] == "running"
    assert active["network_range"] == "192.168.1.0/24"
    assert active["scan_type"] == "full"


def test_get_active_scan_none_when_no_running_scan(db):
    assert db.get_active_scan() is None


# --- update_scan_progress --------------------------------------------------

def test_update_scan_progress_is_visible_in_state(db):
    scan_id = db.create_scan("10.0.0.0/24", "quick")
    db.update_scan_progress(scan_id, "Scanning device 3/8: 10.0.0.5")

    state = db.get_scan_state()
    assert state["running"] is True
    assert state["scan_id"] == scan_id
    assert state["progress"] == "Scanning device 3/8: 10.0.0.5"


# --- get_scan_state idle ---------------------------------------------------

def test_get_scan_state_idle_when_no_scans(db):
    state = db.get_scan_state()
    assert state["running"] is False
    assert state["status"] == "idle"
    assert state["scan_id"] is None
    assert state["last_scan_id"] is None


def test_get_scan_state_idle_when_table_missing(tmp_path):
    """Defensive: a fresh, un-initialized DB returns idle, not an error."""
    manager = DatabaseManager(
        db_type="sqlite", db_path=str(tmp_path / "empty.db")
    )
    manager.connect()  # note: no initialize_schema()
    try:
        state = manager.get_scan_state()
        assert state["running"] is False
        assert state["status"] == "idle"
    finally:
        manager.disconnect()


# --- complete_scan ---------------------------------------------------------

def test_complete_scan_finalizes_row_and_persists_devices(db):
    scan_id = db.create_scan("192.168.1.0/24", "full")
    results = [_make_result(ip="192.168.1.10"), _make_result(ip="192.168.1.11")]

    db.complete_scan(scan_id, results, duration_sec=12.5)

    # Row finalized
    state = db.get_scan_state()
    assert state["running"] is False
    assert state["status"] == "completed"
    assert state["scan_id"] == scan_id
    assert state["last_scan_id"] == scan_id
    assert db.get_active_scan() is None

    # Devices persisted under the SAME scan_id (no duplicate scan row)
    history = db.get_scan_history()
    assert len(history) == 1
    assert history[0]["devices_found"] == 2
    assert round(history[0]["duration_sec"], 1) == 12.5

    devices = db.get_all_devices(scan_id=scan_id)
    assert {d["ip_address"] for d in devices} == {"192.168.1.10", "192.168.1.11"}
    persisted = next(d for d in devices if d["ip_address"] == "192.168.1.10")
    assert persisted["ports"]
    assert persisted["vulnerabilities"]


def test_complete_scan_can_override_network_range(db):
    """Web flow creates the row with a placeholder, then fills the real subnet."""
    scan_id = db.create_scan("auto-detect", "full")
    db.complete_scan(
        scan_id, [_make_result()], duration_sec=1.0,
        network_range="192.168.5.0/24",
    )
    assert db.get_scan_history()[0]["network_range"] == "192.168.5.0/24"


# --- fail_scan -------------------------------------------------------------

def test_fail_scan_marks_failed(db):
    scan_id = db.create_scan("192.168.1.0/24", "full")
    db.fail_scan(scan_id, "nmap exploded")

    state = db.get_scan_state()
    assert state["running"] is False
    assert state["status"] == "failed"
    assert "nmap exploded" in state["progress"]
    assert db.get_active_scan() is None
    # A failed scan is not a valid "last completed" scan
    assert state["last_scan_id"] is None


# --- regression: save_scan still works after refactor ----------------------

def test_save_scan_still_creates_completed_scan(db):
    scan_id = db.save_scan("192.168.1.0/24", "full", [_make_result()], 3.0)
    assert isinstance(scan_id, int)

    state = db.get_scan_state()
    assert state["status"] == "completed"
    assert state["running"] is False
    assert state["scan_id"] == scan_id
    assert state["last_scan_id"] == scan_id

    devices = db.get_all_devices(scan_id=scan_id)
    assert len(devices) == 1
