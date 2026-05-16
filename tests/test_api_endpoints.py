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


def test_scan_stream_yields_complete_event(client):
    from api.app import create_app
    import os
    app = create_app({"db_type": "sqlite", "db_path": ":memory:"})
    app.config["TESTING"] = True
    app.config["SCAN_STATUS"] = {"running": False, "progress": "Done", "last_scan_id": 1}
    with app.test_client() as c:
        r = c.get("/api/scan/stream")
        body = b"".join(r.response)
        assert b"scan_complete" in body
