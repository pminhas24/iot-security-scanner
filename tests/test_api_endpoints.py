import os
import sys
import types
import pytest

_SRC = os.path.join(os.path.dirname(__file__), '..', 'src')
sys.path.insert(0, _SRC)

# Lightweight 'scanner' package stub so importing database.db_manager (which
# imports scanner.models) doesn't pull in the whole scanner runtime
# (paramiko/scapy). app.py imports scanner submodules lazily, and the mocked
# scan tests override them via patch.dict regardless.
if 'scanner' not in sys.modules:
    _pkg = types.ModuleType('scanner')
    _pkg.__path__ = [os.path.join(_SRC, 'scanner')]
    sys.modules['scanner'] = _pkg


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("CONFIG_PATH", str(tmp_path / "config.json"))
    from api.app import create_app
    app = create_app({"db_type": "sqlite", "db_path": ":memory:"})
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def test_settings_get_returns_defaults(client):
    r = client.get("/api/settings")
    assert r.status_code == 200
    data = r.get_json()
    assert "subnet" in data
    assert data["scan_depth"] == "full"


def test_settings_post_and_get(client):
    client.post("/api/settings",
                json={"subnet": "10.0.1.0/24", "scan_depth": "quick"})
    r = client.get("/api/settings")
    data = r.get_json()
    assert data["subnet"] == "10.0.1.0/24"
    assert data["scan_depth"] == "quick"


def test_settings_post_returns_saved(client):
    r = client.post("/api/settings", json={"subnet": "172.16.0.0/24"})
    assert r.status_code == 200
    assert r.get_json()["status"] == "saved"


def test_scan_stream_returns_event_stream(client):
    r = client.get("/api/scan/stream")
    assert r.status_code == 200
    assert "text/event-stream" in r.content_type


def test_scan_status_idle_on_fresh_db(client):
    r = client.get("/api/scan/status")
    assert r.status_code == 200
    data = r.get_json()
    assert data["running"] is False
    assert data["status"] == "idle"


def test_scan_stream_yields_complete_event(tmp_path):
    import threading
    import time
    from api.app import create_app
    from database.db_manager import DatabaseManager

    # A real file DB (not :memory:) so the stream's connection and the
    # "scan worker" connection share state, mirroring multi-worker deploys.
    db_path = str(tmp_path / "stream.db")
    app = create_app({"db_type": "sqlite", "db_path": db_path})
    app.config["TESTING"] = True

    seed = DatabaseManager(db_type="sqlite", db_path=db_path)
    seed.connect()
    seed.initialize_schema()
    scan_id = seed.create_scan("192.168.1.0/24", "full")
    seed.update_scan_progress(scan_id, "Scanning...")
    seed.disconnect()

    def finish():
        time.sleep(0.2)
        d = DatabaseManager(db_type="sqlite", db_path=db_path)
        d.connect()
        d.complete_scan(scan_id, [], duration_sec=0.1)
        d.disconnect()

    t = threading.Thread(target=finish, daemon=True)
    t.start()

    with app.test_client() as c:
        r = c.get("/api/scan/stream")
        body = b"".join(r.response)
        assert b"scan_complete" in body

    t.join(timeout=3)


def test_network_detect_returns_subnet_or_empty(client):
    r = client.get("/api/network/detect")
    assert r.status_code == 200
    data = r.get_json()
    assert "subnet" in data
    assert isinstance(data["subnet"], str)


def test_network_detect_returns_empty_on_failure(client):
    import sys
    from unittest.mock import MagicMock, patch
    mock_nd_module = MagicMock()
    mock_nd_module.NetworkDiscovery.return_value.get_network_range.side_effect = (
        RuntimeError("iface not found")
    )
    with patch.dict(
        sys.modules,
        {"scanner": MagicMock(), "scanner.network_discovery": mock_nd_module},
    ):
        r = client.get("/api/network/detect")
    assert r.status_code == 200
    data = r.get_json()
    assert data["subnet"] == ""
    assert "error" in data


def _mock_scan_modules(captured):
    """Build mocked scanner/database modules for /api/scan/start tests.

    Records the kwargs of interest into `captured` so tests can assert
    what the background scan passed to each component.
    """
    from unittest.mock import MagicMock

    fake_device = MagicMock()
    fake_device.ip_address = "192.168.1.50"

    nd_module = MagicMock()
    nd_instance = nd_module.NetworkDiscovery.return_value
    nd_instance.discover_hosts.return_value = [fake_device]
    nd_instance.get_network_range.return_value = "192.168.1.0/24"

    ps_module = MagicMock()

    def record_scan_device(ip_address, ports=None):
        captured["ports"] = ports
        return MagicMock()

    ps_module.PortScanner.return_value.scan_device.side_effect = record_scan_device

    vc_module = MagicMock()

    def record_vuln_checker(*args, **kwargs):
        captured["vc_kwargs"] = kwargs
        return MagicMock()

    vc_module.VulnerabilityChecker.side_effect = record_vuln_checker

    # Mocked DB: no scan currently running, create_scan hands back an id.
    db_module = MagicMock()
    db_instance = db_module.DatabaseManager.return_value
    db_instance.get_active_scan.return_value = None
    db_instance.create_scan.return_value = 123

    return {
        "scanner": MagicMock(),
        "scanner.network_discovery": nd_module,
        "scanner.port_scanner": ps_module,
        "scanner.device_fingerprinting": MagicMock(),
        "scanner.vulnerability_checker": vc_module,
        "scanner.models": MagicMock(),
        "database": MagicMock(),
        "database.db_manager": db_module,
    }


def _start_scan_and_wait(client, captured, key):
    """POST /api/scan/start and wait for the background thread to do its work.

    Scan state now lives in the DB (mocked here), so we wait on the captured
    side effect rather than an in-memory status flag.
    """
    import time

    r = client.post("/api/scan/start", json={"scan_type": "full"})
    assert r.status_code == 200

    deadline = time.time() + 5
    while time.time() < deadline:
        if key in captured:
            break
        time.sleep(0.05)


def test_scan_uses_custom_ports_from_saved_settings(client):
    from unittest.mock import patch
    import sys

    client.post("/api/settings", json={"custom_ports": "22,80"})

    captured = {}
    with patch.dict(sys.modules, _mock_scan_modules(captured)):
        _start_scan_and_wait(client, captured, "ports")

    assert captured.get("ports") == [22, 80]


def test_scan_passes_dry_run_to_vulnerability_checker(client):
    from unittest.mock import patch
    import sys

    client.post("/api/settings", json={"dry_run": True})

    captured = {}
    with patch.dict(sys.modules, _mock_scan_modules(captured)):
        _start_scan_and_wait(client, captured, "vc_kwargs")

    assert captured.get("vc_kwargs") == {"dry_run": True}
