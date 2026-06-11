"""Smoke test for Phase 5: Database Integration (SQLite)."""
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

TEST_DB = "test_iot_scanner.db"

print("=== Phase 5 Smoke Test (SQLite) ===\n")

# Clean up any previous test DB
if os.path.exists(TEST_DB):
    os.remove(TEST_DB)

# Test 1: Connect and initialize schema
print("--- Database Connection & Schema ---")
db = DatabaseManager(db_type="sqlite", db_path=TEST_DB)
db.connect()
db.initialize_schema()
print("  [PASS] Connected and schema initialized")

# Test 2: Save scan results
print("\n--- Save Scan Results ---")
test_results = [
    DeviceScanResult(
        device=DiscoveredDevice(
            ip_address="192.168.1.1",
            hostname="router",
            mac_address="AA:BB:CC:DD:EE:01",
            vendor="Netgear",
            state="up",
        ),
        port_scan=PortScanResult(
            ip_address="192.168.1.1",
            open_ports=[
                PortInfo(port=80, service="http", is_dangerous=True,
                         danger_reason="HTTP unencrypted", severity=Severity.MEDIUM),
                PortInfo(port=443, service="https"),
                PortInfo(port=22, service="ssh"),
            ],
            dangerous_ports=[
                PortInfo(port=80, service="http", is_dangerous=True,
                         danger_reason="HTTP unencrypted", severity=Severity.MEDIUM),
            ],
        ),
        fingerprint=DeviceFingerprint(
            ip_address="192.168.1.1",
            device_type="router",
            manufacturer="Netgear",
            model="R7000",
        ),
        vulnerability_report=VulnerabilityReport(
            ip_address="192.168.1.1",
            risk_score=33,
            risk_level="medium",
            vulnerabilities=[
                VulnerabilityDetail(
                    vuln_type="dangerous_port", severity=Severity.MEDIUM,
                    details="HTTP unencrypted", port=80,
                ),
                VulnerabilityDetail(
                    vuln_type="default_credentials", severity=Severity.CRITICAL,
                    details="SSH with admin/admin", port=22,
                    remediation="Change password immediately",
                ),
            ],
        ),
    ),
    DeviceScanResult(
        device=DiscoveredDevice(
            ip_address="192.168.1.50",
            hostname="HP-Printer",
            mac_address="AA:BB:CC:DD:EE:02",
            vendor="Hewlett Packard",
            state="up",
        ),
        fingerprint=DeviceFingerprint(
            ip_address="192.168.1.50",
            device_type="printer",
            manufacturer="HP",
            model="LaserJet Pro",
        ),
        vulnerability_report=VulnerabilityReport(
            ip_address="192.168.1.50",
            risk_score=0,
            risk_level="low",
        ),
    ),
    DeviceScanResult(
        device=DiscoveredDevice(
            ip_address="192.168.1.87",
            hostname="Vacuum",
            vendor="Seongji Industry",
            state="up",
        ),
    ),
]

scan_id = db.save_scan(
    network_range="192.168.1.0/24",
    scan_type="full",
    results=test_results,
    duration_sec=15.3,
)
print(f"  [PASS] Saved scan with ID: {scan_id}")

# Test 3: Query all devices
print("\n--- Query All Devices ---")
devices = db.get_all_devices()
print(f"  Found {len(devices)} devices")
assert len(devices) == 3, f"Expected 3 devices, got {len(devices)}"
print("  [PASS] All 3 devices retrieved")

# Check first device (highest risk score should be first)
top_device = devices[0]
assert top_device["ip_address"] == "192.168.1.1"
assert top_device["risk_score"] == 33
assert len(top_device["ports"]) == 3
assert len(top_device["vulnerabilities"]) == 2
print(f"  [PASS] Top device: {top_device['ip_address']} "
      f"(risk={top_device['risk_score']}, "
      f"ports={len(top_device['ports'])}, "
      f"vulns={len(top_device['vulnerabilities'])})")

# Test 4: Query device by IP
print("\n--- Query Device by IP ---")
device = db.get_device_by_ip("192.168.1.50")
assert device is not None
assert device["device_type"] == "printer"
assert device["manufacturer"] == "HP"
print(f"  [PASS] Found printer: {device['manufacturer']} {device['model']}")

# Test 5: Query vulnerabilities
print("\n--- Query Vulnerabilities ---")
all_vulns = db.get_vulnerabilities()
print(f"  Total vulnerabilities: {len(all_vulns)}")
assert len(all_vulns) == 2

critical_vulns = db.get_vulnerabilities(severity="critical")
print(f"  Critical vulnerabilities: {len(critical_vulns)}")
assert len(critical_vulns) == 1
assert critical_vulns[0]["vuln_type"] == "default_credentials"
print("  [PASS] Vulnerability queries working")

# Test 6: Scan history
print("\n--- Scan History ---")
history = db.get_scan_history()
assert len(history) == 1
assert history[0]["network_range"] == "192.168.1.0/24"
assert history[0]["devices_found"] == 3
print(f"  [PASS] Scan history: {history[0]['network_range']}, "
      f"{history[0]['devices_found']} devices")

# Test 7: Risk summary
print("\n--- Risk Summary ---")
summary = db.get_risk_summary()
print(f"  Total: {summary['total_devices']}, "
      f"Critical: {summary['critical']}, "
      f"High: {summary['high']}, "
      f"Medium: {summary['medium']}, "
      f"Low: {summary['low']}")
print(f"  Avg score: {summary['avg_risk_score']}")
assert summary["total_devices"] == 3
assert summary["medium"] == 1
assert summary["low"] == 2
print(f"  Most vulnerable: {summary['most_vulnerable']['ip_address']}")
print("  [PASS] Risk summary correct")

# Cleanup
db.disconnect()
os.remove(TEST_DB)
print(f"\n  Cleaned up {TEST_DB}")

print("\n=== Phase 5 Smoke Tests Complete ===")
