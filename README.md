# IoT Security Scanner

> An active network security scanner that discovers, fingerprints, and assesses IoT devices on a local network — producing a prioritized risk report from a single CLI command or web dashboard.

A modular, automated security assessment platform for discovering and auditing IoT devices on local networks. Designed for home network auditing, enterprise IoT visibility, and cybersecurity portfolio demonstrations.

---

## Description

IoT Security Scanner performs end-to-end security assessment of network-connected devices through a six-phase pipeline: host discovery, port scanning, device fingerprinting, vulnerability detection, database persistence, and a live web dashboard. It identifies exposed services, classifies device types, tests for default credentials, and produces a prioritized risk report — all from a unified CLI or browser interface.

---

## Features

- **Host Discovery** — Ping-sweep any subnet with auto-detected network CIDR
- **Port Scanning** — Service version detection with SYN/TCP fallback; flags dangerous protocols
- **Device Fingerprinting** — Five-layer classification (hostname patterns, MAC vendor, HTTP headers, UPnP/SSDP, port profiles) covering 13 device types and 120+ vendor signatures
- **Vulnerability Detection** — Default credential testing (SSH, Telnet, HTTP Basic Auth) with rate limiting and dry-run safety mode
- **Risk Scoring** — 0–100 composite score per device with CRITICAL / HIGH / MEDIUM / LOW levels
- **Database Persistence** — SQLite (zero-config) backend with full scan history
- **Web Dashboard** — Flask-powered real-time dashboard with REST API, risk charts, and device drill-down
- **Safe Scanning** — Attempt limits, 2-second inter-request delays, lockout thresholds, and `--dry-run` preview mode

---

## Tech Stack

| Network Scanning | `python-nmap` 0.7.1 |
| SSH Auth Testing | `paramiko` |
| HTTP Probing | `requests` |
| Web Framework | `Flask`, `Werkzeug` |
| Database | `sqlite3` (built-in) |
| CLI | `argparse` (stdlib) |
| Terminal UX | `colorama` |
---

## How It Works

```
Phase 1: Network Discovery
  └─ Nmap ping scan (-sn) → active hosts, MACs, hostnames, vendors

Phase 2: Port Scanning
  └─ SYN scan (-sS) with TCP fallback → open ports, service versions, dangerous port flags

Phase 3: Device Fingerprinting
  └─ Hostname regex → MAC vendor table → HTTP Server header + HTML title
     → UPnP/SSDP M-SEARCH → port-profile heuristic → device type + confidence

Phase 4: Vulnerability Detection
  └─ Default credential tests (SSH / Telnet / HTTP Basic Auth)
  └─ Dangerous port flagging with device-type-aware severity
  └─ Risk score accumulation (CRITICAL +25, HIGH +15, MEDIUM +8, LOW +3)

Phase 5: Database Storage
  └─ Writes scan metadata, devices, ports, and vulnerabilities to SQLite or PostgreSQL

Phase 6: Web Dashboard
  └─ Flask serves live risk summary, filterable device table, and REST API
```

---

## Risk Scoring Model

Each device receives a composite risk score on a **0–100 scale**, accumulated from the vulnerabilities found during Phase 4.

**Score accumulation:**

| Severity | Points Added |
|---|---|
| CRITICAL | +25 |
| HIGH | +15 |
| MEDIUM | +8 |
| LOW | +3 |
| INFO | +0 |

Scores are capped at 100. The final score maps to a risk level:

| Score Range | Risk Level |
|---|---|
| 70 – 100 | Critical |
| 50 – 69 | High |
| 30 – 49 | Medium |
| 0 – 29 | Low |

**Context-aware severity:** Severity is not applied uniformly. If a port is expected for the identified device type (e.g., port 554/RTSP on a camera, port 22/SSH on a router), the severity is downgraded — preventing false inflation of risk scores for properly configured devices. Unexpected dangerous ports on the same device type receive full severity weight.

> **Note:** Any device with at least one CRITICAL finding is floored at HIGH risk, regardless of total score.

---

## Active vs Passive Scanning

The scanner operates primarily in **active mode**, where it directly probes targets and generates network traffic. No passive scanning (e.g., ARP monitoring) is currently implemented.

| Technique | Mode | Details |
|---|---|---|
| ICMP ping sweep | Active | Nmap `-sn` sends ICMP echo to enumerate live hosts |
| SYN port scan | Active | Nmap `-sS` sends TCP SYN packets; requires elevated privileges |
| TCP connect scan | Active | Fallback when SYN scan is unavailable; completes full TCP handshake |
| Service version detection | Active | Nmap `-sV` probes open ports to identify software and version |
| HTTP banner grabbing | Active | `requests` fetches `Server` header and page `<title>` from web ports |
| UPnP/SSDP enumeration | Active | Sends multicast M-SEARCH; parses returned device description XML |
| Default credential testing | Active | Paramiko (SSH), raw sockets (Telnet), `requests` (HTTP Basic Auth) |
| Passive ARP monitoring | — | Not implemented; listed as a future improvement |

Nmap scans use the `-T4` timing template (aggressive), which reduces scan time versus the default `-T3` while remaining within acceptable thresholds for local network use.

---

## Scan Workflow Example

A realistic end-to-end audit of a home network:

```bash
# Step 1: Discover all live hosts on the subnet
python cli.py -r 192.168.1.0/24 -v

# Output: Found 14 active devices

# Step 2: Full assessment — port scan + fingerprinting + vuln checks, save to DB and JSON
python cli.py -r 192.168.1.0/24 -p --fingerprint --vuln-check --save-db -o results.json

# Step 3: Launch the dashboard to review and triage results
python cli.py --web
# Open http://localhost:5000 in a browser

# Step 4: Query for critical vulnerabilities via the REST API
curl http://localhost:5000/api/vulnerabilities?severity=critical

# Step 5: Re-audit a single device after remediation
python cli.py -t 192.168.1.23 -p --fingerprint --vuln-check -v
```

**Typical findings on a home network:**

- Router with Telnet (port 23) open → CRITICAL: default credentials accepted
- IP camera with unencrypted HTTP (port 80) and RTSP (port 554) → MEDIUM + HIGH
- Smart TV with no dangerous ports → risk score 0, level: low
- NAS device with SMB (port 445) and FTP (port 21) exposed → HIGH

---

## Real-World Use Cases

**Home network auditing** — Run a full sweep to identify which consumer IoT devices (cameras, smart speakers, routers) expose dangerous services or accept default credentials before a security incident occurs.

**Enterprise IoT visibility** — Enumerate unmanaged or shadow IoT devices joined to a corporate network segment; persist results to PostgreSQL for historical tracking and compliance evidence.

**Pre-deployment device assessment** — Scan a new device in isolation (`-t <ip>`) to baseline its attack surface before adding it to a production network.

**Security awareness demonstrations** — Use `--dry-run` to show stakeholders what a real attacker would test, without triggering lockouts or generating intrusive traffic.

**Incident triage support** — Query the database for all devices with a specific open port or above a risk threshold to quickly scope exposure during an active incident.

---

## Performance and Concurrency

- **Nmap `-T4` timing** is applied to all port scans, using aggressive probe timing to reduce scan duration on local /24 networks versus the default `-T3`.
- **SYN scan (`-sS`)** is attempted first as it is faster than a full TCP connect scan; it falls back to `-sT` automatically if root/admin privileges are unavailable.
- **Per-device port scans** are executed sequentially in the CLI pipeline. No thread pool is used for the scanning phases; parallelism was traded for simplicity and to avoid overwhelming constrained IoT devices.
- **Web dashboard scan triggers** dispatch scans as a **daemon background thread**, returning an immediate HTTP 202 response. A status flag prevents concurrent overlapping scans.
- **Credential testing** is deliberately rate-limited (2-second delay between attempts, 5-attempt cap per service, 3-consecutive-failure lockout) to protect target devices from accidental denial of service.

---

## Safety and Ethical Use

> **This tool is intended for use on networks and devices you own or have explicit written authorization to test. Unauthorized scanning is illegal in most jurisdictions.**

- Only run this scanner against networks and devices you control or have been given written permission to assess.
- Use `--dry-run` to audit the vulnerability check plan before making any connections.
- The credential tester includes hard limits (`max_attempts=5`, `lockout_threshold=3`) specifically to avoid triggering account lockouts on target devices. Do not modify these values carelessly.
- Telnet probing uses raw socket I/O with built-in delays to avoid overwhelming resource-constrained firmware.
- All scan activity is logged to a local file (`scan.log`) for audit trail purposes.
- Results stored in the database may contain sensitive device and credential information — restrict access to the `iot_scanner.db` file and any PostgreSQL credentials accordingly.

---

## Installation

**Prerequisites:** Python 3.8+, Nmap installed and on PATH, root/administrator privileges for SYN scanning.

```bash
# Clone the repository
git clone https://github.com/pminhas24/IoT-Scanner.git
cd IoT-Scanner

# Install dependencies
pip install -r requirements.txt
```

---

## Usage

All functionality is exposed through the unified CLI entry point `cli.py`.

### Network Discovery

```bash
# Discover all active hosts on a subnet
python cli.py -r 192.168.1.0/24

# Scan a single device
python cli.py -t 192.168.1.100

# Quick scan (discovery + ports in one pass)
python cli.py -q -r 192.168.1.0/24
```

### Full Assessment Pipeline

```bash
# Discovery + ports + fingerprinting + vulnerability checks
python cli.py -r 192.168.1.0/24 -p --fingerprint --vuln-check

# Preview vulnerability checks without connecting (dry run)
python cli.py -r 192.168.1.0/24 -p --vuln-check --dry-run

# Custom port list
python cli.py -t 192.168.1.1 -p --ports 22,23,80,443,554,8080
```

### Output and Storage

```bash
# Save results to JSON
python cli.py -r 192.168.1.0/24 -p --fingerprint -o results.json

# Save to SQLite database
python cli.py -r 192.168.1.0/24 -p --fingerprint --vuln-check --save-db

```

### Web Dashboard

```bash
# Launch dashboard at http://localhost:5000
python cli.py --web

# Custom port
python cli.py --web --web-port 8080
```

### Global Flags

| Flag | Description |
|---|---|
| `-v, --verbose` | Enable debug output |
| `-o, --output FILE` | Write results to JSON file |
| `--log-file FILE` | Write logs to file |
| `--dry-run` | Preview vulnerability checks without connecting |

---

## Example Output

**JSON result for a scanned device:**

```json
{
  "ip_address": "192.168.1.145",
  "hostname": "nest-cam-living",
  "mac_address": "18:B4:30:xx:xx:xx",
  "vendor": "Nest Labs",
  "state": "up",
  "port_scan": {
    "open_ports": [
      { "port": 80, "service": "http", "product": "nginx", "is_dangerous": true, "severity": "MEDIUM" },
      { "port": 554, "service": "rtsp", "is_dangerous": true, "severity": "HIGH" }
    ],
    "dangerous_ports": [80, 554]
  },
  "fingerprint": {
    "device_type": "camera",
    "manufacturer": "Nest Labs",
    "model": "Nest Cam IQ",
    "classification_confidence": 0.95
  },
  "vulnerability_report": {
    "risk_score": 23,
    "risk_level": "low",
    "vulnerabilities": [
      {
        "type": "dangerous_port",
        "severity": "MEDIUM",
        "description": "Unencrypted HTTP service exposed on port 80",
        "remediation": "Disable HTTP or redirect to HTTPS"
      }
    ]
  }
}
```

**REST API endpoints:**

```bash
curl http://localhost:5000/api/devices
curl http://localhost:5000/api/vulnerabilities?severity=critical
curl http://localhost:5000/api/risk-summary
curl http://localhost:5000/api/scan/start
```

---

## Supported Protocols / Devices

**Protocols scanned or probed:**

| Protocol | Port(s) | Purpose |
|---|---|---|
| ICMP / Ping | — | Host discovery |
| TCP | All configured | Port scanning, service detection |
| SSH | 22 | Default credential testing via Paramiko |
| Telnet | 23 | Default credential testing via raw socket |
| HTTP | 80, 8080, 8000 | Banner grabbing, HTTP Basic Auth testing |
| HTTPS | 443, 8443 | Encrypted service detection |
| RTSP | 554 | Camera stream port detection |
| UPnP / SSDP | 1900 | Device description XML parsing |
| FTP | 21 | Dangerous service flagging |
| MQTT | 1883 | Port-hint classification |
| CoAP | 5683 | Port-hint classification |
| SMB / RDP / AFP | 445, 3389, 548 | Computer/NAS classification hints |

**Recognized Device Types:**

Router, Camera, Printer, Smart Speaker, Smart Display, Smart Home Hub, Smart Appliance, Media Player, Phone, Computer, Network Storage (NAS), Unknown

---

## Project Structure

```
IoT-Scanner/
├── src/
│   ├── scanner/
│   │   ├── network_discovery.py      # Phase 1: Nmap ping scan, host enumeration
│   │   ├── port_scanner.py           # Phase 2: Service detection, dangerous port classification
│   │   ├── device_fingerprinting.py  # Phase 3: Five-layer device classification
│   │   ├── vulnerability_checker.py  # Phase 4: Credential tests, risk scoring
│   │   ├── models.py                 # Dataclasses: DiscoveredDevice, VulnerabilityReport, etc.
│   │   └── signatures.py             # Vendor/hostname signature database (120+ entries)
│   ├── database/
│   │   └── db_manager.py             # Phase 5: SQLite CRUD + query methods
│   └── api/
│       └── app.py                    # Phase 6: Flask routes (HTML + REST API)
├── static/
│   └── app.js                        # HTMX + Tailwind frontend
├── templates/
│   └── base.html                     # Jinja2 base template
├── tests/                            # pytest test suite
├── dev_run.py                        # Seeds demo data, starts dev server
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── CLAUDE.md
```

---

## Security Capabilities

| Capability | Details |
|---|---|
| Default Credential Testing | 16 username/password pairs tested against SSH, Telnet, and HTTP Basic Auth |
| Dangerous Protocol Detection | Flags Telnet (CRITICAL), FTP (HIGH), RTSP (HIGH), HTTP (MEDIUM) |
| Context-Aware Severity | Severity downgraded when a port is expected for the identified device type |
| Banner Grabbing | HTTP `Server` headers and page titles extracted for fingerprinting |
| UPnP Enumeration | M-SEARCH broadcasts and device description XML parsing |
| Service Version Detection | Nmap `-sV` identifies software products and versions |
| Risk Scoring | 0–100 per-device composite score drives prioritized remediation output |
| Scan History | Full historical records queryable by IP, severity, or date range |

---

## Limitations

- Requires Nmap installed and on PATH; SYN scanning requires root/administrator privileges
- Subnet detection assumes a /24 mask; non-standard CIDRs require manual `-r` input
- Default credential list covers common IoT defaults only — not a full brute-force tool
- No active CVE database integration; vulnerability detection is rule-based, not CVE-matched
- UPnP/SSDP discovery is limited to devices that respond on the local broadcast segment
- Web dashboard scan triggers use background threads with no persistent job queue
- MQTT and CoAP payloads are not actively probed — only port presence is noted

---

## Future Improvements

- CVE lookup integration (NVD / Shodan API) for version-based vulnerability matching
- MQTT broker interaction testing (unauthenticated subscribe/publish checks)
- CoAP active probing (`GET /.well-known/core` resource discovery)
- Scheduled recurring scans with change-detection alerts
- Export to PDF / CSV for audit reporting
- Docker image with pre-configured PostgreSQL backend
- Passive scanning mode (ARP monitoring) to reduce active traffic footprint
- Plugin interface for custom vulnerability checks and device signatures

---


## License

MIT License — see [LICENSE](LICENSE) for details.
