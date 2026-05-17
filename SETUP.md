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
