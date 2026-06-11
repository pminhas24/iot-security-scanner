# IoT Security Scanner — Project Context

## What This Is
A network-based IoT security scanning tool that discovers devices on a local network,
fingerprints them, checks for vulnerabilities (default creds, open ports, weak services),
and reports findings with plain-English AI summaries. Target user: non-technical home lab
owners and small business owners. Goal: deployed, publicly accessible, production-quality.

## Stack (actual, verified)
- **Language:** Python 3.11+
- **Web framework:** Flask (not FastAPI)
- **Frontend:** HTMX + Tailwind via CDN, served by Flask (not React)
- **Scanning:** python-nmap 0.7.1, argparse CLI (not Click)
- **Database:** SQLite via sqlite3 (PostgreSQL code exists but is broken — ignore it)
- **Containerization:** Docker + docker-compose
- **Production server:** Gunicorn behind Nginx (target; dev currently uses Flask dev server)
- **AI summary:** Anthropic API, claude-sonnet-4-20250514
- **CVE lookup:** NVD API (https://nvd.nist.gov/developers/vulnerabilities)
- **Auth:** Flask-Session + bcrypt (to be added in Phase 2)
- **Deployment target:** AWS EC2 t3.micro, Ubuntu 22.04, DuckDNS subdomain, Let's Encrypt SSL

## Project Structure (actual)
```
iot-security-scanner/
├── src/
│   ├── scanner/
│   │   ├── network_discovery.py
│   │   ├── port_scanner.py
│   │   ├── device_fingerprinter.py
│   │   ├── vulnerability_checker.py
│   │   ├── models.py              # dataclasses, DeviceType enum, RiskLevel enum
│   │   └── __init__.py
│   ├── database/
│   │   ├── db_manager.py
│   │   └── __init__.py
│   ├── api/
│   │   ├── app.py                 # Flask app, all routes
│   │   └── __init__.py
│   └── cli.py                     # argparse CLI entry point
├── static/
│   └── app.js                     # HTMX frontend (the live one)
├── templates/
│   └── base.html
├── tests/
│   └── (pytest test files)
├── dev_run.py                     # Seeds demo data, starts dev server
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── CLAUDE.md
├── README.md
└── .github/
    └── workflows/
        └── ci.yml                 # GitHub Actions (to be added Phase 1)
```

## Build & Run Commands
```bash
# Install dependencies (system Python, not venv — venv missing pytest)
pip install -r requirements.txt

# Run with demo data (dev)
python dev_run.py

# Run tests
pytest tests/

# Docker (dev)
docker compose up --build

# Docker (prod) — after Phase 2
docker compose -f docker-compose.prod.yml up -d
```

## Known Issues — Do Not Reintroduce
- PostgreSQL path in db_manager.py is broken (cursor.description clobbered in loop). 
  SQLite only until explicitly fixed.
- Flask dev server (app.run) is used in Docker CMD — must be replaced with Gunicorn for prod.
- Scan state lives in app.config dict — must move to DB before multi-worker deployment.
- demo data in dev_run.py uses device types not in DeviceType enum — fix taxonomy drift first.

## Coding Rules
- Always write tests before implementing a feature (TDD). Run pytest after every change.
- Use parameterized queries for all DB operations — never string-format SQL.
- Type hints required on all function signatures.
- Never use sys.path.insert hacks — the project will be made installable via pyproject.toml.
- One feature per session. Do not refactor unrelated code while implementing a feature.
- After any change, run: `pytest tests/ && flake8 src/ tests/`
- Do not add dependencies without updating requirements.txt.
- Do not touch static/js/dashboard.js or static/css/style.css — dead code, will be deleted.

## Phase Roadmap
- **Phase 0 (NOW):** Git cleanup, README accuracy, risk scoring fix, settings wiring
- **Phase 1:** CI/CD, pyproject.toml, Gunicorn/Nginx, scan state in DB, taxonomy fix
- **Phase 2:** NVD CVE integration, real-time SSE, auth (bcrypt + Flask-Session), AI summary, PDF export
- **Phase 3:** EC2 deployment, DuckDNS + SSL, monitoring

## Environment Variables (add to .env, never commit)
```
ANTHROPIC_API_KEY=
NVD_API_KEY=           # optional, raises rate limit from 5/30s to 50/30s
SCANNER_PASSWORD=      # bcrypt-hashed admin password (Phase 2)
FLASK_SECRET_KEY=      # for Flask-Session
```

## Interview Talking Points (know these cold)
- Custom Telnet IAC negotiation handler in vulnerability_checker.py — wrote it because
  telnetlib was removed in Python 3.13
- Context-aware severity downgrading: SSH on a router is expected, Telnet on a camera is not
- WAL mode + parameterized queries + transactions with rollback in db_manager.py
- Non-root Docker user on slim image
- Rate limiting + lockout threshold in vuln checker to avoid bricking devices
