# IoT Scanner — Docker + HTMX Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Package the IoT Scanner as a single Docker container with a polished HTMX-powered web dashboard accessible at `http://localhost:5000`.

**Architecture:** Flask serves both the UI (Jinja2 + HTMX + Tailwind CDN) and the existing REST API. A new SSE endpoint streams live scan progress. A config module persists user settings to `/data/config.json` on a Docker volume alongside the SQLite database.

**Tech Stack:** Python 3.11-slim, Nmap (apt), Flask + HTMX 1.9 (CDN), Tailwind CSS (CDN), SQLite on Docker volume.

---

## File Map

| Action | Path | Responsibility |
|--------|------|----------------|
| Create | `Dockerfile` | Single-stage image: Python + Nmap, runs CLI in web mode |
| Create | `docker-compose.yml` | Volume, network_mode host, port 5000 |
| Create | `.dockerignore` | Exclude venv, .git, __pycache__ |
| Create | `src/api/config.py` | Read/write `/data/config.json` via `CONFIG_PATH` env var |
| Modify | `src/api/app.py` | Add `/api/settings`, `/api/network/detect`, `/api/scan/stream` routes |
| Create | `src/frontend/templates/base.html` | Tailwind + HTMX base; header with risk counts, scan button, settings panel |
| Create | `src/frontend/templates/index.html` | Device table, extends base |
| Create | `src/frontend/templates/device_detail.html` | Port + vuln detail, extends base |
| Create | `src/frontend/static/app.js` | JS helpers: startScan, SSE handler, settings load/save, toggleSettings |
| Create | `SETUP.md` | Plain-English user setup guide |
| Create | `tests/test_config.py` | Unit tests for `src/api/config.py` |
| Create | `tests/test_api_endpoints.py` | Flask test client tests for new endpoints |

---

## Task 1: Docker infrastructure

**Files:**
- Create: `Dockerfile`
- Create: `docker-compose.yml`
- Create: `.dockerignore`

> No automated tests for config files — manual verification step at end.

- [ ] **Step 1: Create `.dockerignore`**

```
venv/
.git/
__pycache__/
*.pyc
*.pyo
.superpowers/
docs/
tests/
*.md
nul
```

Save to `.dockerignore` at project root.

- [ ] **Step 2: Create `Dockerfile`**

```dockerfile
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/

ENV PYTHONPATH=/app/src

VOLUME /data
EXPOSE 5000

CMD ["python", "src/cli.py", "--web", "--db-path", "/data/iot_scanner.db"]
```

Save to `Dockerfile` at project root.

- [ ] **Step 3: Create `docker-compose.yml`**

```yaml
version: "3.9"

services:
  scanner:
    build: .
    volumes:
      - scanner_data:/data
    environment:
      - CONFIG_PATH=/data/config.json
    network_mode: host   # Required on Linux for Nmap to see local network
    # On Windows/Mac: comment out network_mode and uncomment the two lines below
    # ports:
    #   - "5000:5000"

volumes:
  scanner_data:
```

Save to `docker-compose.yml` at project root.

- [ ] **Step 4: Verify build (manual)**

```bash
docker build -t iot-scanner-test .
```

Expected: build completes with no errors. Nmap appears in `apt-get install` output.

- [ ] **Step 5: Commit**

```bash
git add Dockerfile docker-compose.yml .dockerignore
git commit -m "feat: add Docker infrastructure"
```

---

## Task 2: Config module

**Files:**
- Create: `src/api/config.py`
- Create: `tests/test_config.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_config.py`:

```python
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
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
cd "C:\Users\sarda\OneDrive\Desktop\Projects\IOT scanner"
python -m pytest tests/test_config.py -v
```

Expected: `ModuleNotFoundError: No module named 'api.config'`

- [ ] **Step 3: Implement `src/api/config.py`**

```python
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
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
python -m pytest tests/test_config.py -v
```

Expected: 4 passed.

- [ ] **Step 5: Commit**

```bash
git add src/api/config.py tests/test_config.py
git commit -m "feat: add config module for persisting scan settings"
```

---

## Task 3: New API endpoints (settings, network detect, SSE stream)

**Files:**
- Modify: `src/api/app.py`
- Create: `tests/test_api_endpoints.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_api_endpoints.py`:

```python
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
    # Simulate idle state (no scan running, no prior progress)
    r = client.get("/api/scan/stream")
    assert r.status_code == 200
    assert "text/event-stream" in r.content_type


def test_scan_stream_yields_complete_event(client):
    # Pre-set status so generator exits quickly
    from api.app import create_app
    import os
    app = create_app({"db_type": "sqlite", "db_path": ":memory:"})
    app.config["TESTING"] = True
    app.config["SCAN_STATUS"] = {"running": False, "progress": "Done", "last_scan_id": 1}
    with app.test_client() as c:
        r = c.get("/api/scan/stream")
        body = b"".join(r.response)
        assert b"scan_complete" in body
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
python -m pytest tests/test_api_endpoints.py -v
```

Expected: failures on `settings` routes and `scan/stream` (routes don't exist yet).

- [ ] **Step 3: Add the three new routes to `src/api/app.py`**

Add `Response, stream_with_context` to the Flask import at the top of `app.py`:

```python
from flask import Flask, render_template, jsonify, request, abort, Response, stream_with_context
```

Then add these three route blocks **inside** `create_app()`, after the existing `api_risk_summary` route and before the final `return app`:

```python
    @app.route("/api/settings", methods=["GET"])
    def api_settings_get():
        """GET /api/settings - Return current scan settings."""
        from api import config
        return jsonify(config.load())

    @app.route("/api/settings", methods=["POST"])
    def api_settings_save():
        """POST /api/settings - Persist scan settings."""
        from api import config
        data = request.get_json(silent=True) or {}
        config.save(data)
        return jsonify({"status": "saved"})

    @app.route("/api/network/detect")
    def api_network_detect():
        """GET /api/network/detect - Auto-detect local subnet."""
        try:
            from scanner.network_discovery import NetworkDiscovery
            subnet = NetworkDiscovery().get_network_range()
            return jsonify({"subnet": subnet})
        except Exception as e:
            return jsonify({"subnet": "", "error": str(e)})

    @app.route("/api/scan/stream")
    def api_scan_stream():
        """GET /api/scan/stream - SSE stream of scan progress."""
        def _generate():
            last_progress = None
            while True:
                status = app.config["SCAN_STATUS"]
                progress = status["progress"]
                running = status["running"]

                if progress != last_progress:
                    import json as _json
                    yield f"data: {_json.dumps({'progress': progress, 'running': running})}\n\n"
                    last_progress = progress

                if not running and last_progress is not None:
                    yield "event: scan_complete\ndata: {\"done\": true}\n\n"
                    return

                time.sleep(0.5)

        return Response(
            stream_with_context(_generate()),
            mimetype="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
python -m pytest tests/test_api_endpoints.py -v
```

Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
git add src/api/app.py tests/test_api_endpoints.py
git commit -m "feat: add settings, network detect, and SSE scan stream endpoints"
```

---

## Task 4: Base HTML template

**Files:**
- Create: `src/frontend/templates/base.html`
- Create: `src/frontend/static/app.js`

> Note: `src/api/app.py` sets `template_folder` to `src/frontend/templates` and `static_folder` to `src/frontend/static`. Create those directories as part of this task.

- [ ] **Step 1: Create `src/frontend/templates/base.html`**

```html
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{% block title %}IoT Scanner{% endblock %}</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script>tailwind.config = { darkMode: 'class' }</script>
  <script src="https://unpkg.com/htmx.org@1.9.12" defer></script>
</head>
<body class="bg-gray-950 text-gray-100 min-h-screen">

  <!-- Header -->
  <header class="bg-gray-900 border-b border-gray-800 px-6 py-3 flex flex-wrap items-center gap-4">
    <a href="/" class="font-bold text-lg text-white tracking-tight">IoT Scanner</a>

    <div class="flex gap-5 text-sm ml-2">
      <span class="text-red-400">🔴 Critical: <strong id="count-critical">{{ risk_summary.critical if risk_summary else 0 }}</strong></span>
      <span class="text-orange-400">🟠 High: <strong id="count-high">{{ risk_summary.high if risk_summary else 0 }}</strong></span>
      <span class="text-yellow-400">🟡 Med: <strong id="count-medium">{{ risk_summary.medium if risk_summary else 0 }}</strong></span>
      <span class="text-green-400">🟢 Low: <strong id="count-low">{{ risk_summary.low if risk_summary else 0 }}</strong></span>
    </div>

    <div class="ml-auto flex gap-2">
      <button id="scan-btn"
              onclick="startScan()"
              class="bg-blue-600 hover:bg-blue-700 disabled:opacity-50 px-4 py-1.5 rounded text-sm font-medium transition-colors">
        Scan My Network
      </button>
      <button onclick="toggleSettings()"
              class="bg-gray-700 hover:bg-gray-600 px-3 py-1.5 rounded text-sm transition-colors">
        ⚙ Settings
      </button>
    </div>
  </header>

  <!-- Settings panel (hidden by default) -->
  <div id="settings-panel" class="hidden bg-gray-900 border-b border-gray-800 px-6 py-4">
    <form onsubmit="saveSettings(event)" class="flex flex-wrap gap-4 items-end">
      <div>
        <label class="block text-xs text-gray-400 mb-1 uppercase tracking-wide">Subnet</label>
        <input id="setting-subnet" type="text" placeholder="192.168.1.0/24"
               class="bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm w-48 focus:outline-none focus:border-blue-500">
      </div>
      <div>
        <label class="block text-xs text-gray-400 mb-1 uppercase tracking-wide">Scan Depth</label>
        <select id="setting-depth"
                class="bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm focus:outline-none focus:border-blue-500">
          <option value="full">Full (ports + fingerprint + vulns)</option>
          <option value="quick">Quick (discovery + ports only)</option>
        </select>
      </div>
      <div>
        <label class="block text-xs text-gray-400 mb-1 uppercase tracking-wide">Custom Ports</label>
        <input id="setting-ports" type="text" placeholder="22,80,443,8080"
               class="bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm w-44 focus:outline-none focus:border-blue-500">
      </div>
      <label class="flex items-center gap-2 cursor-pointer">
        <input id="setting-dryrun" type="checkbox" class="rounded accent-blue-500">
        <span class="text-sm text-gray-300">Dry Run</span>
      </label>
      <button type="submit"
              class="bg-green-700 hover:bg-green-600 px-4 py-1.5 rounded text-sm transition-colors">
        Save Settings
      </button>
    </form>
  </div>

  <!-- Scan progress bar (hidden when idle) -->
  <div id="progress-container" class="hidden bg-gray-800 border-b border-gray-700 px-6 py-2">
    <div class="flex items-center gap-3">
      <div class="animate-spin h-4 w-4 border-2 border-blue-500 border-t-transparent rounded-full flex-shrink-0"></div>
      <span id="progress-text" class="text-sm text-gray-300">Scanning...</span>
    </div>
  </div>

  <!-- Flash error (optional) -->
  {% if error %}
  <div class="bg-red-900 border border-red-700 text-red-200 px-6 py-3 text-sm">
    ⚠ {{ error }}
  </div>
  {% endif %}

  <main class="px-6 py-6">
    {% block content %}{% endblock %}
  </main>

  <script src="{{ url_for('static', filename='app.js') }}"></script>
</body>
</html>
```

- [ ] **Step 2: Create `src/frontend/static/app.js`**

```javascript
function toggleSettings() {
  const panel = document.getElementById('settings-panel');
  panel.classList.toggle('hidden');
  if (!panel.classList.contains('hidden')) {
    _loadSettings();
  }
}

function _loadSettings() {
  fetch('/api/settings')
    .then(r => r.json())
    .then(s => {
      document.getElementById('setting-subnet').value = s.subnet || '';
      document.getElementById('setting-depth').value = s.scan_depth || 'full';
      document.getElementById('setting-ports').value = s.custom_ports || '';
      document.getElementById('setting-dryrun').checked = !!s.dry_run;
      if (!s.subnet) {
        fetch('/api/network/detect')
          .then(r => r.json())
          .then(d => {
            if (d.subnet) document.getElementById('setting-subnet').value = d.subnet;
          });
      }
    });
}

function saveSettings(e) {
  e.preventDefault();
  const settings = {
    subnet: document.getElementById('setting-subnet').value.trim(),
    scan_depth: document.getElementById('setting-depth').value,
    custom_ports: document.getElementById('setting-ports').value.trim(),
    dry_run: document.getElementById('setting-dryrun').checked,
  };
  fetch('/api/settings', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(settings),
  }).then(() => {
    document.getElementById('settings-panel').classList.add('hidden');
  });
}

function startScan() {
  fetch('/api/settings')
    .then(r => r.json())
    .then(settings => {
      const body = {
        scan_type: settings.scan_depth || 'full',
        network_range: settings.subnet || null,
      };
      return fetch('/api/scan/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
    })
    .then(r => r.json())
    .then(data => {
      if (data.error) {
        alert(data.error);
        return;
      }
      document.getElementById('scan-btn').disabled = true;
      document.getElementById('progress-container').classList.remove('hidden');
      _connectSseStream();
    });
}

function _connectSseStream() {
  const evtSource = new EventSource('/api/scan/stream');

  evtSource.onmessage = function (e) {
    const data = JSON.parse(e.data);
    document.getElementById('progress-text').textContent = data.progress || 'Scanning...';
  };

  evtSource.addEventListener('scan_complete', function () {
    evtSource.close();
    document.getElementById('progress-container').classList.add('hidden');
    document.getElementById('scan-btn').disabled = false;
    window.location.reload();
  });

  evtSource.onerror = function () {
    evtSource.close();
    document.getElementById('progress-text').textContent = 'Scan interrupted — check logs.';
    document.getElementById('scan-btn').disabled = false;
  };
}
```

- [ ] **Step 3: Verify Flask can locate the templates (manual)**

```bash
cd "C:\Users\sarda\OneDrive\Desktop\Projects\IOT scanner"
set PYTHONPATH=src
python -c "from api.app import create_app; app = create_app(); print('OK')"
```

Expected: `OK` with no errors.

- [ ] **Step 4: Commit**

```bash
git add src/frontend/templates/base.html src/frontend/static/app.js
git commit -m "feat: add base template and client-side JS"
```

---

## Task 5: Dashboard template (index page)

**Files:**
- Create: `src/frontend/templates/index.html`

- [ ] **Step 1: Create `src/frontend/templates/index.html`**

```html
{% extends "base.html" %}
{% block title %}Dashboard — IoT Scanner{% endblock %}

{% block content %}

{% if not devices %}
  <div class="text-center py-24">
    <p class="text-gray-400 text-lg mb-2">No scan results yet.</p>
    <p class="text-gray-600 text-sm">Click <strong class="text-white">Scan My Network</strong> in the header to run your first scan.</p>
  </div>
{% else %}

  <!-- Device table -->
  <div class="overflow-x-auto rounded-lg border border-gray-800">
    <table class="w-full text-sm">
      <thead class="bg-gray-900 text-gray-400 uppercase text-xs tracking-wide">
        <tr>
          <th class="px-4 py-3 text-left">Device / IP</th>
          <th class="px-4 py-3 text-left">Hostname</th>
          <th class="px-4 py-3 text-left">Type</th>
          <th class="px-4 py-3 text-left">Vendor</th>
          <th class="px-4 py-3 text-center">Open Ports</th>
          <th class="px-4 py-3 text-center">Risk Score</th>
          <th class="px-4 py-3 text-center">Risk Level</th>
        </tr>
      </thead>
      <tbody class="divide-y divide-gray-800">
        {% for device in devices %}
        {% set risk = device.risk_level | default('low') | lower %}
        {% set row_class = {
            'critical': 'bg-red-950 hover:bg-red-900',
            'high':     'bg-orange-950 hover:bg-orange-900',
            'medium':   'bg-yellow-950 hover:bg-yellow-900',
            'low':      'bg-gray-900 hover:bg-gray-800',
        }.get(risk, 'bg-gray-900 hover:bg-gray-800') %}
        {% set badge = {
            'critical': 'bg-red-600 text-white',
            'high':     'bg-orange-500 text-white',
            'medium':   'bg-yellow-500 text-black',
            'low':      'bg-green-700 text-white',
        }.get(risk, 'bg-gray-600 text-white') %}
        <tr class="{{ row_class }} cursor-pointer transition-colors"
            onclick="window.location='/device/{{ device.ip_address }}'">
          <td class="px-4 py-3 font-mono font-medium text-white">{{ device.ip_address }}</td>
          <td class="px-4 py-3 text-gray-300">{{ device.hostname or '—' }}</td>
          <td class="px-4 py-3 text-gray-300 capitalize">{{ device.device_type or 'Unknown' }}</td>
          <td class="px-4 py-3 text-gray-400">{{ device.vendor or '—' }}</td>
          <td class="px-4 py-3 text-center text-gray-300">
            {% if device.ports %}
              <span class="font-mono text-xs">{% for p in device.ports %}{{ p.port }}{% if not loop.last %}, {% endif %}{% endfor %}</span>
            {% else %}
              <span class="text-gray-600">—</span>
            {% endif %}
          </td>
          <td class="px-4 py-3 text-center font-bold text-white">{{ device.risk_score | default(0) }}</td>
          <td class="px-4 py-3 text-center">
            <span class="px-2 py-0.5 rounded text-xs font-semibold uppercase {{ badge }}">
              {{ risk }}
            </span>
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>

  <!-- Scan history -->
  {% if scan_history %}
  <div class="mt-8">
    <h2 class="text-sm text-gray-400 uppercase tracking-wide mb-3">Recent Scans</h2>
    <div class="flex flex-col gap-1">
      {% for scan in scan_history %}
      <div class="text-xs text-gray-500 font-mono">
        {{ scan.scan_date }} — {{ scan.scan_type }} — {{ scan.network_range }} — {{ scan.device_count }} devices
      </div>
      {% endfor %}
    </div>
  </div>
  {% endif %}

{% endif %}
{% endblock %}
```

- [ ] **Step 2: Verify the dashboard renders (manual)**

With `PYTHONPATH=src` set, run:

```bash
python src/cli.py --web
```

Open `http://localhost:5000`. Expected: dark dashboard with "No scan results yet" or device table if DB has data. Header should show risk counts. Settings panel should open on ⚙ click.

- [ ] **Step 3: Commit**

```bash
git add src/frontend/templates/index.html
git commit -m "feat: add dashboard index template"
```

---

## Task 6: Device detail template

**Files:**
- Create: `src/frontend/templates/device_detail.html`

- [ ] **Step 1: Create `src/frontend/templates/device_detail.html`**

```html
{% extends "base.html" %}
{% block title %}{{ device.ip_address }} — IoT Scanner{% endblock %}

{% block content %}
{% set risk = device.risk_level | default('low') | lower %}
{% set badge = {
    'critical': 'bg-red-600 text-white',
    'high':     'bg-orange-500 text-white',
    'medium':   'bg-yellow-500 text-black',
    'low':      'bg-green-700 text-white',
}.get(risk, 'bg-gray-600 text-white') %}

<div class="mb-4">
  <a href="/" class="text-sm text-gray-500 hover:text-gray-300 transition-colors">← Back to Dashboard</a>
</div>

<!-- Device summary card -->
<div class="bg-gray-900 border border-gray-800 rounded-lg p-6 mb-6">
  <div class="flex flex-wrap items-start justify-between gap-4">
    <div>
      <h1 class="text-2xl font-bold font-mono text-white mb-1">{{ device.ip_address }}</h1>
      <p class="text-gray-400">{{ device.hostname or 'No hostname' }}</p>
    </div>
    <div class="text-right">
      <div class="text-4xl font-bold text-white mb-1">{{ device.risk_score | default(0) }}<span class="text-lg text-gray-500">/100</span></div>
      <span class="px-3 py-1 rounded text-sm font-semibold uppercase {{ badge }}">{{ risk }}</span>
    </div>
  </div>

  <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mt-6 text-sm">
    <div>
      <div class="text-xs text-gray-500 uppercase mb-1">Type</div>
      <div class="text-white capitalize">{{ device.device_type or 'Unknown' }}</div>
    </div>
    <div>
      <div class="text-xs text-gray-500 uppercase mb-1">Vendor</div>
      <div class="text-white">{{ device.vendor or '—' }}</div>
    </div>
    <div>
      <div class="text-xs text-gray-500 uppercase mb-1">MAC Address</div>
      <div class="text-white font-mono">{{ device.mac_address or '—' }}</div>
    </div>
    <div>
      <div class="text-xs text-gray-500 uppercase mb-1">Model</div>
      <div class="text-white">{{ device.model or '—' }}</div>
    </div>
  </div>
</div>

<!-- Open ports -->
{% if device.ports %}
<div class="bg-gray-900 border border-gray-800 rounded-lg p-6 mb-6">
  <h2 class="text-sm text-gray-400 uppercase tracking-wide mb-4">Open Ports</h2>
  <table class="w-full text-sm">
    <thead class="text-xs text-gray-500 uppercase">
      <tr>
        <th class="text-left pb-2">Port</th>
        <th class="text-left pb-2">Service</th>
        <th class="text-left pb-2">Product / Version</th>
        <th class="text-left pb-2">Risk</th>
      </tr>
    </thead>
    <tbody class="divide-y divide-gray-800">
      {% for port in device.ports %}
      {% set sev = port.severity | default('') | upper %}
      {% set sev_color = {
          'CRITICAL': 'text-red-400',
          'HIGH':     'text-orange-400',
          'MEDIUM':   'text-yellow-400',
          'LOW':      'text-green-400',
      }.get(sev, 'text-gray-500') %}
      <tr>
        <td class="py-2 font-mono text-white">{{ port.port }}/tcp</td>
        <td class="py-2 text-gray-300">{{ port.service or '—' }}</td>
        <td class="py-2 text-gray-400">{{ ((port.product or '') + ' ' + (port.version or '')) | trim or '—' }}</td>
        <td class="py-2 {{ sev_color }} text-xs font-semibold">{{ sev or '—' }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</div>
{% endif %}

<!-- Vulnerabilities -->
{% if device.vulnerabilities %}
<div class="bg-gray-900 border border-gray-800 rounded-lg p-6">
  <h2 class="text-sm text-gray-400 uppercase tracking-wide mb-4">Vulnerabilities</h2>
  <div class="flex flex-col gap-3">
    {% for vuln in device.vulnerabilities %}
    {% set sev = vuln.severity | default('') | upper %}
    {% set border = {
        'CRITICAL': 'border-red-600',
        'HIGH':     'border-orange-500',
        'MEDIUM':   'border-yellow-500',
        'LOW':      'border-green-600',
    }.get(sev, 'border-gray-600') %}
    {% set badge_class = {
        'CRITICAL': 'bg-red-600 text-white',
        'HIGH':     'bg-orange-500 text-white',
        'MEDIUM':   'bg-yellow-500 text-black',
        'LOW':      'bg-green-700 text-white',
    }.get(sev, 'bg-gray-600 text-white') %}
    <div class="border-l-4 {{ border }} pl-4 py-2">
      <div class="flex items-center gap-2 mb-1">
        <span class="px-2 py-0.5 rounded text-xs font-bold {{ badge_class }}">{{ sev }}</span>
        <span class="text-white text-sm font-medium">{{ vuln.vuln_type or vuln.type or '—' }}</span>
      </div>
      <p class="text-gray-400 text-sm">{{ vuln.description or vuln.details or '—' }}</p>
      {% if vuln.remediation %}
      <p class="text-green-400 text-xs mt-1">Fix: {{ vuln.remediation }}</p>
      {% endif %}
    </div>
    {% endfor %}
  </div>
</div>
{% else %}
<div class="bg-gray-900 border border-gray-800 rounded-lg p-6 text-center text-gray-500 text-sm">
  No vulnerabilities detected.
</div>
{% endif %}

{% endblock %}
```

- [ ] **Step 2: Verify device detail page (manual)**

With a scan already saved to DB, visit `http://localhost:5000/device/<ip>`. Expected: dark card with IP, risk badge, port table, and vuln list. "Back to Dashboard" link works.

- [ ] **Step 3: Commit**

```bash
git add src/frontend/templates/device_detail.html
git commit -m "feat: add device detail template"
```

---

## Task 7: SETUP.md user guide

**Files:**
- Create: `SETUP.md`

- [ ] **Step 1: Create `SETUP.md`**

```markdown
# IoT Scanner — Setup Guide

Scan your home or office network for IoT devices and security issues — no command-line knowledge needed after the one-time setup.

---

## Requirements

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (Windows or Mac) or Docker Engine (Linux)
- A machine connected to the network you want to scan

> **Admin/root required:** Nmap needs elevated privileges for accurate scanning. Docker Desktop on Windows runs with sufficient privileges. On Linux, run `docker compose up` with `sudo` if you get permission errors.

---

## Quick Start

**1. Get the files**

Download or clone this repository:

```bash
git clone https://github.com/pminhas24/IoT-Scanner.git
cd IoT-Scanner
```

**2. Start the scanner**

```bash
docker compose up
```

The first run downloads dependencies — this takes a few minutes. Subsequent starts are instant.

**3. Open the dashboard**

Visit [http://localhost:5000](http://localhost:5000) in your browser.

**4. Scan your network**

Click **Scan My Network**. Devices appear as they're discovered — a typical home network takes 2–5 minutes for a full scan.

**5. Stop the scanner**

Press `Ctrl+C` in the terminal where you ran `docker compose up`.

Your results are saved and will be there next time you start.

---

## Settings

Click **⚙ Settings** in the top-right corner to adjust:

| Setting | Default | Description |
|---------|---------|-------------|
| Subnet | Auto-detected | The network range to scan (e.g. `192.168.1.0/24`) |
| Scan Depth | Full | Full runs all checks; Quick only discovers hosts and open ports |
| Custom Ports | — | Override the default port list (comma-separated) |
| Dry Run | Off | Shows what would be tested without making any connections |

---

## Windows & Mac Note

Docker on Windows and Mac runs inside a virtual machine. This means:

- The scanner **can** discover devices and open ports via TCP
- MAC addresses and vendor names **will not appear** (ARP is not accessible through the VM)
- For full MAC/vendor data, run on a Linux machine

---

## Updating

```bash
docker compose pull   # if using a published image
docker compose up --build   # if building locally
```

---

## Data & Privacy

All scan results are stored locally in a Docker volume on your machine. Nothing is sent to any external server.

To delete all stored data:

```bash
docker compose down -v
```

---

## Troubleshooting

**"Address already in use" on port 5000**
Another app is using port 5000. Edit `docker-compose.yml`, change `5000:5000` to `5001:5000`, then open `http://localhost:5001`.

**Scan finds 0 devices**
- Make sure your machine is connected to the network (not VPN-only)
- Check the subnet in Settings — it should match your network (e.g. `192.168.1.0/24`)
- On Linux, try running with `sudo docker compose up`

**Dashboard shows "Scanner unavailable — Nmap missing"**
Rebuild the image: `docker compose up --build`
```

- [ ] **Step 2: Commit**

```bash
git add SETUP.md
git commit -m "docs: add user setup guide"
```

---

## Task 8: End-to-end verification

- [ ] **Step 1: Run all tests**

```bash
python -m pytest tests/ -v
```

Expected: all tests pass.

- [ ] **Step 2: Build and run Docker image**

```bash
docker compose up --build
```

Open `http://localhost:5000`. Expected: dark dashboard loads without errors.

- [ ] **Step 3: Verify settings panel**

Click ⚙ Settings. Expected: panel slides open with subnet pre-filled (auto-detected).

- [ ] **Step 4: Verify scan button**

Click **Scan My Network**. Expected: button disables, progress bar appears with live status text updates, results populate after scan completes.

- [ ] **Step 5: Verify device detail**

Click any device row. Expected: detail page loads with IP, risk badge, port table, and vulnerability list.

- [ ] **Step 6: Final commit**

```bash
git add .
git commit -m "chore: end-to-end verification complete"
```
