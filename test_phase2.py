"""Quick smoke test for Phase 2 modules."""
import sys
sys.path.insert(0, "src")

from scanner.models import (
    Severity, PortInfo, PortScanResult, DeviceScanResult,
    DeviceType, DeviceFingerprint, VulnerabilityReport,
)
from scanner.port_scanner import PortScanner, PortScanError
from scanner.network_discovery import NetworkDiscovery, DiscoveredDevice

print("=== Phase 2 Smoke Test ===\n")

# 1. Test model creation
pi = PortInfo(
    port=23, service="telnet", is_dangerous=True,
    danger_reason="Telnet - credentials in plaintext",
    severity=Severity.CRITICAL,
)
print("PortInfo:", pi.to_dict())

psr = PortScanResult(
    ip_address="192.168.1.1",
    open_ports=[pi],
    dangerous_ports=[pi],
    scan_timestamp="2026-02-10T12:00:00Z",
)
print("PortScanResult keys:", list(psr.to_dict().keys()))

# 2. Test DeviceScanResult composition
device = DiscoveredDevice(ip_address="192.168.1.1", hostname="test-router", vendor="Netgear")
dsr = DeviceScanResult(device=device, port_scan=psr)
result_dict = dsr.to_dict()
print("DeviceScanResult keys:", list(result_dict.keys()))
assert "port_scan" in result_dict
assert result_dict["ip_address"] == "192.168.1.1"
assert len(result_dict["port_scan"]["open_ports"]) == 1

# 3. Test PortScanner class attributes
print("\nDEFAULT_PORTS:", PortScanner.DEFAULT_PORTS)
print("DANGEROUS_PORTS count:", len(PortScanner.DANGEROUS_PORTS))
print("Severity for port 23:", PortScanner.get_severity_for_port(23))
print("Severity for port 443:", PortScanner.get_severity_for_port(443))

# 4. Test port classification
ps = PortScanner.__new__(PortScanner)
ps.DANGEROUS_PORTS = PortScanner.DANGEROUS_PORTS
classified = ps._classify_port(23, "telnet", "BusyBox telnetd", "1.0")
assert classified.is_dangerous is True
assert classified.severity == Severity.CRITICAL
print("\nPort 23 classified correctly as CRITICAL danger")

classified_safe = ps._classify_port(443, "https", "nginx", "1.25")
assert classified_safe.is_dangerous is False
assert classified_safe.severity == Severity.INFO
print("Port 443 classified correctly as safe/INFO")

classified_ftp_alt = ps._classify_port(2121, "ftp", "vsftpd", "3.0")
assert classified_ftp_alt.is_dangerous is True
assert classified_ftp_alt.severity == Severity.HIGH
print("Port 2121 (FTP on alt port) classified correctly as HIGH danger")

# 5. Test NetworkDiscovery.scanner property
nd = NetworkDiscovery()
assert nd.scanner is not None
print("\nNetworkDiscovery.scanner property works:", type(nd.scanner).__name__)

# 6. Test backward compatibility of __init__.py
from scanner import NetworkDiscovery as ND2
assert ND2 is NetworkDiscovery
print("scanner.__init__.py backward compatibility: OK")

print("\n=== All Phase 2 tests PASSED ===")
