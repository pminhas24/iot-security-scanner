# IoT Scanner — Docker Packaging & HTMX Dashboard Redesign

**Date:** 2026-05-15  
**Status:** Approved

---

## Goal

Transform the existing IoT Security Scanner into a self-contained, user-friendly product that security-minded hobbyists (and home users / small-business IT staff) can run with a single `docker run` command and immediately use via a browser dashboard — no CLI knowledge required after initial setup.

---

## Target Users

**Primary:** Security-minded hobbyists — understand IP addresses and networking basics, want a polished tool without writing code or using a terminal beyond initial setup.  
**Secondary:** Home users auditing their own network, IT staff at small businesses.

---

## Deployment Model

**Fully self-hosted Docker container.** No cloud backend. No ongoing cost for the maintainer. All data stays on the user's machine.

- User installs Docker Desktop (Windows/Mac) or Docker Engine (Linux)
- Runs one command: `docker compose up`
- Opens `http://localhost:5000` in their browser
- Everything — scanner, web UI, database — runs inside the container
- SQLite database persists in a named Docker volume across restarts

---

## Architecture

```
[ Browser ] ──HTTP──► [ Flask + HTMX UI  :5000 ]
                              │
                       [ Scanner Pipeline ]   ← background thread (existing)
                              │
                       [ SQLite via volume ]  ← scan history persists
```

Single container. Single port. No external services.

### Network mode constraint

Nmap requires `network_mode: host` on Linux to perform SYN scans and read ARP/MAC data from the local network. On Windows and macOS, Docker runs inside a VM — the scanner will discover TCP-reachable devices but will not see MAC addresses or ARP data. The setup guide will document this limitation clearly.

---

## What Changes

### Frontend (`src/api/frontend/`) — full overhaul

| Component | Change |
|---|---|
| CSS | Replace hand-written styles with Tailwind CSS loaded via CDN (no build step) |
| JavaScript | Replace `dashboard.js` with HTMX attributes for live updates |
| Nav / header | Risk-level summary bar always visible: Critical / High / Medium / Low counts + "Scan" button + Settings toggle |
| Dashboard page | Sortable device table, rows color-coded by risk level, clickable for drill-down |
| Settings panel | Collapsible panel: subnet field, scan depth selector (Quick / Full), custom port list |
| Scan progress | Live feed via Server-Sent Events (SSE) — devices appear as they are discovered |
| Device detail | Existing drill-down page restyled with Tailwind |

### Docker files — new

| File | Purpose |
|---|---|
| `Dockerfile` | Single-stage Python 3.11-slim image; installs Nmap + pip deps; entrypoint runs `python src/cli.py --web` |
| `docker-compose.yml` | Named volume for SQLite, port 5000 mapped, `network_mode: host` for Linux |
| `SETUP.md` | One-page plain-English setup guide (install Docker → run command → open browser) |

### What does NOT change

- `src/scanner/` — all 6 pipeline phases untouched
- `src/database/` — db_manager, schema untouched
- `src/cli.py` — still works as a standalone CLI
- `src/api/app.py` Flask routes and REST API — routes untouched; only templates/static files are replaced

---

## UI Design

### Layout (Summary-First, Option A)

```
┌─────────────────────────────────────────────────────────────┐
│  IoT Scanner   🔴 Critical: 2  🟠 High: 5  🟡 Med: 8  🟢 Low: 12  │
│                                      [ Scan My Network ] [⚙] │
├─────────────────────────────────────────────────────────────┤
│  [scan progress bar / status message — hidden when idle]    │
├─────────────────────────────────────────────────────────────┤
│  Device          │ Type    │ Risk Score │ Risk Level │ Ports │
│  192.168.1.1     │ Router  │ 87         │ 🔴 CRITICAL│ 23,80 │
│  192.168.1.23    │ Camera  │ 62         │ 🟠 HIGH    │ 80,554│
│  192.168.1.45    │ NAS     │ 38         │ 🟡 MEDIUM  │ 21,445│
│  192.168.1.10    │ Smart TV│ 4          │ 🟢 LOW     │ —     │
├─────────────────────────────────────────────────────────────┤
│  ⚙ Settings (collapsible)                                   │
│  Subnet: [192.168.1.0/24]  Depth: [Full ▼]  Ports: [...]   │
└─────────────────────────────────────────────────────────────┘
```

### Settings panel (collapsible, hidden by default)

- **Subnet** — text input, pre-filled with auto-detected CIDR
- **Scan depth** — dropdown: Quick (ping + top ports) / Full (all phases)
- **Custom ports** — comma-separated port list (optional override)
- **Dry run** — checkbox (preview vuln checks without connecting)
- Save button writes settings to `/data/config.json` (same Docker volume as SQLite) read by the Flask app at scan time

### Scan progress (HTMX + SSE)

When the user clicks "Scan My Network":
1. Button disables, progress bar appears with status text ("Discovering hosts…")
2. SSE stream from `/api/scan/stream` pushes updates: phase name + devices found so far
3. Device table rows appear incrementally as each device completes
4. On completion, progress bar hides and summary counts update

---

## Docker Setup Guide outline (`SETUP.md`)

1. Install Docker Desktop (link to docker.com)
2. Download or clone this repo
3. Run: `docker compose up`
4. Open `http://localhost:5000`
5. Click "Scan My Network"
6. **Note for Windows/Mac users:** MAC addresses won't appear due to Docker's VM networking — this is expected

---

## Error Handling

- If Nmap is not found inside the container → flash banner: "Scanner unavailable — Nmap missing"
- If a scan is already running → "Scan already in progress" banner, button stays disabled
- If subnet auto-detection fails → settings panel opens automatically with subnet field focused
- Network errors during SSE stream → progress bar shows "Scan interrupted — check logs"

---

## Out of Scope

- Cloud hosting / multi-user auth
- CVE database integration
- PDF/CSV export
- Passive ARP monitoring
- Plugin interface

These remain listed as future improvements in the README.
