"""Smoke test for Phase 6: Web Dashboard."""
import json
import os
import sys
sys.path.insert(0, "src")

from scanner.models import (
    DeviceScanResult, PortScanResult, PortInfo, Severity,
    DeviceFingerprint, VulnerabilityReport, VulnerabilityDetail,
)
from scanner.network_discovery import DiscoveredDevice
from database.db_manager import DatabaseManager
from api.app import create_app

TEST_DB = "test_dashboard.db"

print("=== Phase 6 Smoke Test (Web Dashboard) ===\n")

# Clean up
if os.path.exists(TEST_DB):
    os.remove(TEST_DB)

# --- Seed test data ---
print("--- Seeding Test Database ---")
db = DatabaseManager(db_type="sqlite", db_path=TEST_DB)
db.connect()
db.initialize_schema()

test_results = [
    DeviceScanResult(
        device=DiscoveredDevice(
            ip_address="192.168.1.1", hostname="router",
            mac_address="AA:BB:CC:DD:EE:01", vendor="Netgear", state="up",
        ),
        port_scan=PortScanResult(
            ip_address="192.168.1.1",
            open_ports=[
                PortInfo(port=80, service="http", is_dangerous=True,
                         danger_reason="HTTP unencrypted", severity=Severity.MEDIUM),
                PortInfo(port=443, service="https"),
                PortInfo(port=23, service="telnet", is_dangerous=True,
                         danger_reason="Telnet plaintext", severity=Severity.CRITICAL),
            ],
            dangerous_ports=[
                PortInfo(port=80, service="http", is_dangerous=True,
                         danger_reason="HTTP unencrypted", severity=Severity.MEDIUM),
                PortInfo(port=23, service="telnet", is_dangerous=True,
                         danger_reason="Telnet plaintext", severity=Severity.CRITICAL),
            ],
        ),
        fingerprint=DeviceFingerprint(
            ip_address="192.168.1.1", device_type="router",
            manufacturer="Netgear", model="R7000",
        ),
        vulnerability_report=VulnerabilityReport(
            ip_address="192.168.1.1", risk_score=73, risk_level="critical",
            vulnerabilities=[
                VulnerabilityDetail(
                    vuln_type="default_credentials", severity=Severity.CRITICAL,
                    details="SSH with admin/admin", port=22,
                    remediation="Change password immediately",
                ),
                VulnerabilityDetail(
                    vuln_type="dangerous_port", severity=Severity.CRITICAL,
                    details="Telnet open", port=23,
                    remediation="Disable Telnet, use SSH",
                ),
                VulnerabilityDetail(
                    vuln_type="dangerous_port", severity=Severity.MEDIUM,
                    details="HTTP unencrypted", port=80,
                    remediation="Use HTTPS",
                ),
            ],
        ),
    ),
    DeviceScanResult(
        device=DiscoveredDevice(
            ip_address="192.168.1.50", hostname="HP-Printer",
            mac_address="AA:BB:CC:DD:EE:02", vendor="Hewlett Packard", state="up",
        ),
        port_scan=PortScanResult(
            ip_address="192.168.1.50",
            open_ports=[
                PortInfo(port=80, service="http"),
                PortInfo(port=631, service="ipp"),
            ],
            dangerous_ports=[],
        ),
        fingerprint=DeviceFingerprint(
            ip_address="192.168.1.50", device_type="printer",
            manufacturer="HP", model="LaserJet Pro M404n",
        ),
        vulnerability_report=VulnerabilityReport(
            ip_address="192.168.1.50", risk_score=8, risk_level="low",
            vulnerabilities=[
                VulnerabilityDetail(
                    vuln_type="dangerous_port", severity=Severity.MEDIUM,
                    details="HTTP unencrypted web interface", port=80,
                ),
            ],
        ),
    ),
    DeviceScanResult(
        device=DiscoveredDevice(
            ip_address="192.168.1.87", hostname="Vacuum",
            vendor="Seongji Industry", state="up",
        ),
        fingerprint=DeviceFingerprint(
            ip_address="192.168.1.87", device_type="smart_appliance",
            manufacturer="Seongji", model="RoboVac X1",
        ),
        vulnerability_report=VulnerabilityReport(
            ip_address="192.168.1.87", risk_score=0, risk_level="low",
        ),
    ),
]

scan_id = db.save_scan("192.168.1.0/24", "full", test_results, 25.7)
db.disconnect()
print(f"  Seeded scan_id={scan_id} with {len(test_results)} devices")

# --- Create Flask test client ---
print("\n--- Flask App Tests ---")
app = create_app(db_config={"db_type": "sqlite", "db_path": TEST_DB})
app.config["TESTING"] = True
client = app.test_client()

# Test 1: Dashboard home
print("\n  GET / (dashboard)")
response = client.get("/")
assert response.status_code == 200
html = response.data.decode("utf-8")
assert "192.168.1.1" in html
assert "Netgear" in html
assert "CRITICAL" in html
assert "Total Devices" in html
print("  [PASS] Dashboard renders with device data")

# Test 2: Device detail page
print("\n  GET /device/192.168.1.1 (device detail)")
response = client.get("/device/192.168.1.1")
assert response.status_code == 200
html = response.data.decode("utf-8")
assert "192.168.1.1" in html
assert "R7000" in html
assert "Telnet" in html or "telnet" in html
assert "73" in html  # risk score
print("  [PASS] Device detail renders with ports and vulns")

# Test 3: 404 for unknown device
response = client.get("/device/10.0.0.1")
assert response.status_code == 404
print("  [PASS] 404 for unknown device")

# Test 4: API - devices list
print("\n  GET /api/devices")
response = client.get("/api/devices")
assert response.status_code == 200
data = response.get_json()
assert data["count"] == 3
assert len(data["devices"]) == 3
# Verify sorted by risk_score descending
assert data["devices"][0]["ip_address"] == "192.168.1.1"
assert data["devices"][0]["risk_score"] == 73
print(f"  [PASS] API returns {data['count']} devices, sorted by risk")

# Test 5: API - device detail
print("\n  GET /api/devices/192.168.1.50")
response = client.get("/api/devices/192.168.1.50")
assert response.status_code == 200
data = response.get_json()
assert data["device_type"] == "printer"
assert data["model"] == "LaserJet Pro M404n"
assert len(data["ports"]) == 2
assert len(data["vulnerabilities"]) == 1
print(f"  [PASS] API device detail: {data['device_type']} with "
      f"{len(data['ports'])} ports, {len(data['vulnerabilities'])} vulns")

# Test 6: API - device not found
response = client.get("/api/devices/10.0.0.1")
assert response.status_code == 404
print("  [PASS] API 404 for unknown device")

# Test 7: API - vulnerabilities
print("\n  GET /api/vulnerabilities")
response = client.get("/api/vulnerabilities")
assert response.status_code == 200
data = response.get_json()
assert data["count"] == 4  # 3 from router + 1 from printer
print(f"  [PASS] API returns {data['count']} vulnerabilities")

# Test 8: API - filter vulnerabilities by severity
response = client.get("/api/vulnerabilities?severity=critical")
data = response.get_json()
assert data["count"] == 2
print(f"  [PASS] API critical vulns filter: {data['count']}")

# Test 9: API - risk summary
print("\n  GET /api/risk-summary")
response = client.get("/api/risk-summary")
assert response.status_code == 200
data = response.get_json()
assert data["total_devices"] == 3
assert data["critical"] == 1
assert data["low"] == 2
print(f"  [PASS] Risk summary: {data['total_devices']} devices, "
      f"critical={data['critical']}, low={data['low']}")

# Test 10: API - scan status
print("\n  GET /api/scan/status")
response = client.get("/api/scan/status")
assert response.status_code == 200
data = response.get_json()
assert data["running"] is False
print(f"  [PASS] Scan status: running={data['running']}")

# Test 11: Static files accessible
print("\n  GET /static/css/style.css")
response = client.get("/static/css/style.css")
assert response.status_code == 200
assert b"--bg-primary" in response.data
print("  [PASS] CSS file served")

response = client.get("/static/js/dashboard.js")
assert response.status_code == 200
assert b"startScan" in response.data
print("  [PASS] JS file served")

# Cleanup
os.remove(TEST_DB)
print(f"\n  Cleaned up {TEST_DB}")

print("\n=== Phase 6 Smoke Tests Complete (all passed) ===")
