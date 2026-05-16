import json
import os
from pathlib import Path

_DEFAULTS = {
    "subnet": "",
    "scan_depth": "full",
    "custom_ports": "",
    "dry_run": False,
}


def _path() -> Path:
    return Path(os.environ.get("CONFIG_PATH", "data/config.json"))


def load() -> dict:
    p = _path()
    if not p.exists():
        return dict(_DEFAULTS)
    try:
        with open(p) as f:
            data = json.load(f)
        return {**_DEFAULTS, **{k: v for k, v in data.items() if k in _DEFAULTS}}
    except (json.JSONDecodeError, OSError):
        return dict(_DEFAULTS)


def save(settings: dict) -> None:
    p = _path()
    p.parent.mkdir(parents=True, exist_ok=True)
    clean = {k: v for k, v in settings.items() if k in _DEFAULTS}
    with open(p, "w") as f:
        json.dump(clean, f, indent=2)
