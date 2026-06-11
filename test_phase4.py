"""Smoke test for Phase 4: Vulnerability Detection."""
import sys
sys.path.insert(0, "src")

from scanner.models import (
    Severity, PortInfo, PortScanResult, DeviceFingerprint,
    VulnerabilityDetail,
)
from scanner.vulnerability_checker import VulnerabilityChecker
from scanner.network_discovery import DiscoveredDevice

print("=== Phase 4 Smoke Test ===\n")

vc = VulnerabilityChecker(dry_run=True)

# Test 1: Risk score computation
print("--- Risk Score Computation ---")
test_cases = [
    ([], 0, "low"),
    (
        [VulnerabilityDetail(vuln_type="test", severity=Severity.CRITICAL)],
        25, "low",
    ),
    (
        [
            VulnerabilityDetail(vuln_type="test", severity=Severity.CRITICAL),
            VulnerabilityDetail(vuln_type="test", severity=Severity.CRITICAL),
            VulnerabilityDetail(vuln_type="test", severity=Severity.HIGH),
        ],
        65, "high",
    ),
    (
        [
            VulnerabilityDetail(vuln_type="test", severity=Severity.CRITICAL),
            VulnerabilityDetail(vuln_type="test", severity=Severity.CRITICAL),
            VulnerabilityDetail(vuln_type="test", severity=Severity.CRITICAL),
        ],
        75, "critical",
    ),
    (
        [VulnerabilityDetail(vuln_type="test", severity=Severity.MEDIUM)] * 4,
        32, "medium",
    ),
]

for vulns, expected_score, expected_level in test_cases:
    score, level = vc._compute_risk_score(vulns)
    status = "PASS" if score == expected_score and level == expected_level else "FAIL"
    print(f"  [{status}] {len(vulns)} vulns -> score={score} (expected {expected_score}), "
          f"level={level} (expected {expected_level})")

# Test 2: Dangerous port flagging
print("\n--- Dangerous Port Flagging ---")
port_scan = PortScanResult(
    ip_address="192.168.1.1",
    open_ports=[
        PortInfo(port=23, service="telnet", is_dangerous=True,
                 danger_reason="Telnet unencrypted", severity=Severity.CRITICAL),
        PortInfo(port=80, service="http", is_dangerous=True,
                 danger_reason="HTTP unencrypted", severity=Severity.MEDIUM),
        PortInfo(port=443, service="https", is_dangerous=False, severity=Severity.INFO),
    ],
    dangerous_ports=[
        PortInfo(port=23, service="telnet", is_dangerous=True,
                 danger_reason="Telnet unencrypted", severity=Severity.CRITICAL),
        PortInfo(port=80, service="http", is_dangerous=True,
                 danger_reason="HTTP unencrypted", severity=Severity.MEDIUM),
    ],
)

# Test with router fingerprint (telnet/http expected)
fp_router = DeviceFingerprint(ip_address="192.168.1.1", device_type="router")
port_vulns = vc._flag_dangerous_ports(port_scan, fp_router)
print(f"  Router with telnet+http: {len(port_vulns)} vulns")
for v in port_vulns:
    print(f"    [{v.severity.value.upper()}] port {v.port}: {v.details[:60]}...")

# Telnet should be downgraded from CRITICAL to HIGH for router
telnet_vuln = [v for v in port_vulns if v.port == 23][0]
status = "PASS" if telnet_vuln.severity == Severity.HIGH else "FAIL"
print(f"  [{status}] Telnet on router: {telnet_vuln.severity.value} "
      f"(expected high, downgraded from critical)")

# Test with camera fingerprint (telnet NOT expected)
fp_camera = DeviceFingerprint(ip_address="192.168.1.1", device_type="camera")
port_vulns_cam = vc._flag_dangerous_ports(port_scan, fp_camera)
telnet_vuln_cam = [v for v in port_vulns_cam if v.port == 23][0]
status = "PASS" if telnet_vuln_cam.severity == Severity.CRITICAL else "FAIL"
print(f"  [{status}] Telnet on camera: {telnet_vuln_cam.severity.value} "
      f"(expected critical, NOT expected port)")

# Test 3: Dry-run mode
print("\n--- Dry Run Mode ---")
device = DiscoveredDevice(ip_address="192.168.1.87", vendor="Test")
port_scan_ssh = PortScanResult(
    ip_address="192.168.1.87",
    open_ports=[
        PortInfo(port=22, service="ssh"),
        PortInfo(port=80, service="http", is_dangerous=True,
                 danger_reason="HTTP unencrypted", severity=Severity.MEDIUM),
    ],
    dangerous_ports=[
        PortInfo(port=80, service="http", is_dangerous=True,
                 danger_reason="HTTP unencrypted", severity=Severity.MEDIUM),
    ],
)

report = vc.check(device, port_scan=port_scan_ssh)
print(f"  Risk score: {report.risk_score}, level: {report.risk_level}")
print(f"  Vulnerabilities found: {len(report.vulnerabilities)}")
for v in report.vulnerabilities:
    print(f"    [{v.severity.value.upper()}] {v.vuln_type}: {v.details[:70]}...")

dry_run_vulns = [v for v in report.vulnerabilities if "DRY RUN" in v.details]
status = "PASS" if len(dry_run_vulns) >= 1 else "FAIL"
print(f"  [{status}] Dry run generated {len(dry_run_vulns)} preview vulns")

# Test 4: Full report to_dict
print("\n--- Report Serialization ---")
report_dict = report.to_dict()
required_keys = {"ip_address", "risk_score", "risk_level", "vulnerabilities"}
has_keys = required_keys.issubset(set(report_dict.keys()))
status = "PASS" if has_keys else "FAIL"
print(f"  [{status}] Report dict has required keys: {list(report_dict.keys())}")

# Test 5: Score capping at 100
print("\n--- Score Capping ---")
many_vulns = [
    VulnerabilityDetail(vuln_type="test", severity=Severity.CRITICAL)
    for _ in range(10)
]
score, level = vc._compute_risk_score(many_vulns)
status = "PASS" if score == 100 else "FAIL"
print(f"  [{status}] 10 CRITICAL vulns -> score={score} (expected 100, capped)")

print("\n=== Phase 4 Smoke Tests Complete ===")
