"""Smoke test for Phase 3: Device Fingerprinting."""
import json
import sys
sys.path.insert(0, "src")

from scanner.models import DeviceType, PortScanResult, PortInfo, Severity
from scanner.device_fingerprinting import DeviceFingerprinter
from scanner.network_discovery import DiscoveredDevice

print("=== Phase 3 Smoke Test ===\n")

fp = DeviceFingerprinter()

# Test 1: Vendor-based classification
test_cases = [
    ("Hewlett Packard", "", "printer"),
    ("TP-Link Systems", "NETGEAR", "router"),      # hostname NETGEAR -> router
    ("Google", "", "smart_speaker"),
    ("The Chamberlain Group", "", "smart_appliance"),
    ("Seongji Industry", "", "smart_appliance"),
    ("Samsung Electronics", "", "phone"),
    ("Nest Labs", "", "camera"),
]

print("--- Vendor/Hostname Classification ---")
for vendor, hostname, expected_type in test_cases:
    device = DiscoveredDevice(
        ip_address="192.168.1.1",
        hostname=hostname,
        vendor=vendor,
    )
    result = fp.fingerprint(device)
    status = "PASS" if result.device_type == expected_type else "FAIL"
    print(f"  [{status}] vendor='{vendor}', hostname='{hostname}' -> "
          f"{result.device_type} (expected: {expected_type}, "
          f"confidence={result.classification_confidence})")
    if status == "FAIL":
        print(f"         GOT: {result.device_type}")

# Test 2: Hostname pattern classification
hostname_cases = [
    ("Nest-Cam-ABC123", "camera"),
    ("HP-LaserJet-Pro", "printer"),
    ("MyVacuumCleaner", "smart_appliance"),
    ("Living-Room-Chromecast", "media_player"),
    ("Synology-NAS", "network_storage"),
]

print("\n--- Hostname Pattern Classification ---")
for hostname, expected_type in hostname_cases:
    device = DiscoveredDevice(ip_address="192.168.1.1", hostname=hostname)
    result = fp.fingerprint(device)
    status = "PASS" if result.device_type == expected_type else "FAIL"
    print(f"  [{status}] hostname='{hostname}' -> {result.device_type} "
          f"(expected: {expected_type})")

# Test 3: Port profile heuristic
print("\n--- Port Profile Classification ---")
# RTSP camera
camera_ports = PortScanResult(
    ip_address="192.168.1.50",
    open_ports=[
        PortInfo(port=554, service="rtsp"),
        PortInfo(port=80, service="http"),
    ],
)
device = DiscoveredDevice(ip_address="192.168.1.50")
result = fp.fingerprint(device, port_scan=camera_ports)
status = "PASS" if result.device_type == "camera" else "FAIL"
print(f"  [{status}] RTSP+HTTP -> {result.device_type} (expected: camera)")

# Printer
printer_ports = PortScanResult(
    ip_address="192.168.1.60",
    open_ports=[
        PortInfo(port=631, service="ipp"),
        PortInfo(port=9100, service="jetdirect"),
    ],
)
device = DiscoveredDevice(ip_address="192.168.1.60")
result = fp.fingerprint(device, port_scan=printer_ports)
status = "PASS" if result.device_type == "printer" else "FAIL"
print(f"  [{status}] IPP+JetDirect -> {result.device_type} (expected: printer)")

# Test 4: Real scan data from results.json
print("\n--- Real Scan Data Classification ---")
try:
    with open("results.json") as f:
        real_devices = json.load(f)

    classified = {}
    for d in real_devices:
        device = DiscoveredDevice(
            ip_address=d["ip_address"],
            hostname=d.get("hostname", ""),
            mac_address=d.get("mac_address", ""),
            vendor=d.get("vendor", ""),
        )
        result = fp.fingerprint(device)
        classified[d["ip_address"]] = result.device_type
        if result.device_type != "unknown":
            print(f"  {d['ip_address']:16} vendor='{d.get('vendor', ''):25}' "
                  f"-> {result.device_type} "
                  f"(confidence={result.classification_confidence})")

    known = sum(1 for t in classified.values() if t != "unknown")
    print(f"\n  Classified {known}/{len(classified)} devices "
          f"({100*known/len(classified):.0f}%)")
except FileNotFoundError:
    print("  results.json not found, skipping real data test")

print("\n=== Phase 3 Smoke Tests Complete ===")
