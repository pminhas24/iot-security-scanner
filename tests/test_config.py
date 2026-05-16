import json
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))


def test_load_returns_defaults_when_no_file(tmp_path, monkeypatch):
    monkeypatch.setenv("CONFIG_PATH", str(tmp_path / "config.json"))
    from api import config
    import importlib; importlib.reload(config)
    result = config.load()
    assert result["subnet"] == ""
    assert result["scan_depth"] == "full"
    assert result["dry_run"] is False


def test_save_and_load_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("CONFIG_PATH", str(tmp_path / "config.json"))
    from api import config
    import importlib; importlib.reload(config)
    config.save({"subnet": "10.0.0.0/24", "scan_depth": "quick", "custom_ports": "22,80", "dry_run": True})
    result = config.load()
    assert result["subnet"] == "10.0.0.0/24"
    assert result["scan_depth"] == "quick"
    assert result["dry_run"] is True


def test_save_ignores_unknown_keys(tmp_path, monkeypatch):
    monkeypatch.setenv("CONFIG_PATH", str(tmp_path / "config.json"))
    from api import config
    import importlib; importlib.reload(config)
    config.save({"subnet": "192.168.0.0/24", "evil_key": "injected"})
    result = config.load()
    assert "evil_key" not in result


def test_load_handles_corrupt_file(tmp_path, monkeypatch):
    path = tmp_path / "config.json"
    path.write_text("not json")
    monkeypatch.setenv("CONFIG_PATH", str(path))
    from api import config
    import importlib; importlib.reload(config)
    result = config.load()
    assert result["subnet"] == ""
