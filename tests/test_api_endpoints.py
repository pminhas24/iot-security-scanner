import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))


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


def test_scan_stream_yields_complete_event():
    import threading
    import time
    from api.app import create_app
    app = create_app({"db_type": "sqlite", "db_path": ":memory:"})
    app.config["TESTING"] = True
    app.config["SCAN_STATUS"]["running"] = True
    app.config["SCAN_STATUS"]["progress"] = "Scanning..."

    def finish():
        time.sleep(0.2)
        app.config["SCAN_STATUS"]["running"] = False
        app.config["SCAN_STATUS"]["progress"] = "Done"

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

    return {
        "scanner": MagicMock(),
        "scanner.network_discovery": nd_module,
        "scanner.port_scanner": ps_module,
        "scanner.device_fingerprinting": MagicMock(),
        "scanner.vulnerability_checker": vc_module,
        "scanner.models": MagicMock(),
        "database": MagicMock(),
        "database.db_manager": MagicMock(),
    }


def _start_scan_and_wait(client, captured, key):
    """POST /api/scan/start and wait for the background thread to finish."""
    import time

    r = client.post("/api/scan/start", json={"scan_type": "full"})
    assert r.status_code == 200

    status = client.application.config["SCAN_STATUS"]
    deadline = time.time() + 5
    while time.time() < deadline:
        if key in captured and not status["running"]:
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
