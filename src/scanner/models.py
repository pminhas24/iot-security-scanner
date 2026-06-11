"""
Shared Data Models for the IoT Security Scanner.

Defines dataclasses used across all scanner modules. Each phase adds
its own dataclass; the composite DeviceScanResult aggregates them all.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

# Re-export for backward compatibility
from .network_discovery import DiscoveredDevice


class Severity(Enum):
    """Severity levels for vulnerabilities and port dangers."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class DeviceType(Enum):
    """Classification categories for IoT devices."""
    ROUTER = "router"
    CAMERA = "camera"
    PRINTER = "printer"
    SMART_SPEAKER = "smart_speaker"
    SMART_DISPLAY = "smart_display"
    SMART_HOME_HUB = "smart_home_hub"
    SMART_APPLIANCE = "smart_appliance"
    MEDIA_PLAYER = "media_player"
    PHONE = "phone"
    COMPUTER = "computer"
    NETWORK_STORAGE = "network_storage"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Phase 2: Port Scanning
# ---------------------------------------------------------------------------

@dataclass
class PortInfo:
    """Detailed information about a single open port."""
    port: int
    protocol: str = "tcp"
    service: str = "unknown"
    product: str = ""
    version: str = ""
    is_dangerous: bool = False
    danger_reason: str = ""
    severity: Severity = Severity.INFO

    def to_dict(self) -> dict:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "service": self.service,
            "product": self.product,
            "version": self.version,
            "is_dangerous": self.is_dangerous,
            "danger_reason": self.danger_reason,
            "severity": self.severity.value,
        }


@dataclass
class PortScanResult:
    """Results of a port scan on a single device."""
    ip_address: str
    open_ports: list[PortInfo] = field(default_factory=list)
    dangerous_ports: list[PortInfo] = field(default_factory=list)
    scan_timestamp: str = ""

    def to_dict(self) -> dict:
        return {
            "ip_address": self.ip_address,
            "open_ports": [p.to_dict() for p in self.open_ports],
            "dangerous_ports": [p.to_dict() for p in self.dangerous_ports],
            "scan_timestamp": self.scan_timestamp,
        }


# ---------------------------------------------------------------------------
# Phase 3: Device Fingerprinting
# ---------------------------------------------------------------------------

@dataclass
class DeviceFingerprint:
    """Classification and identification data for a device."""
    ip_address: str
    device_type: str = "unknown"
    manufacturer: str = ""
    model: str = ""
    firmware_version: str = ""
    classification_confidence: float = 0.0

    def to_dict(self) -> dict:
        return {
            "ip_address": self.ip_address,
            "device_type": self.device_type,
            "manufacturer": self.manufacturer,
            "model": self.model,
            "firmware_version": self.firmware_version,
            "classification_confidence": self.classification_confidence,
        }


# ---------------------------------------------------------------------------
# Phase 4: Vulnerability Detection
# ---------------------------------------------------------------------------

@dataclass
class VulnerabilityDetail:
    """A single vulnerability finding."""
    vuln_type: str
    severity: Severity = Severity.INFO
    details: str = ""
    remediation: str = ""
    port: Optional[int] = None

    def to_dict(self) -> dict:
        return {
            "type": self.vuln_type,
            "severity": self.severity.value,
            "details": self.details,
            "remediation": self.remediation,
            "port": self.port,
        }


@dataclass
class VulnerabilityReport:
    """Aggregate vulnerability results for a single device."""
    ip_address: str
    risk_score: int = 0
    risk_level: str = "low"
    vulnerabilities: list[VulnerabilityDetail] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "ip_address": self.ip_address,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
        }


# ---------------------------------------------------------------------------
# Composite Result
# ---------------------------------------------------------------------------

@dataclass
class DeviceScanResult:
    """
    Composite result aggregating all phases for one device.

    The pipeline builds this incrementally:
      1. device        ← NetworkDiscovery
      2. port_scan     ← PortScanner       (Phase 2)
      3. fingerprint   ← DeviceFingerprinter (Phase 3)
      4. vulnerability_report ← VulnerabilityChecker (Phase 4)
    """
    device: DiscoveredDevice
    port_scan: Optional[PortScanResult] = None
    fingerprint: Optional[DeviceFingerprint] = None
    vulnerability_report: Optional[VulnerabilityReport] = None

    def to_dict(self) -> dict:
        result = self.device.to_dict()
        if self.port_scan:
            result["port_scan"] = self.port_scan.to_dict()
        if self.fingerprint:
            result["fingerprint"] = self.fingerprint.to_dict()
        if self.vulnerability_report:
            result["vulnerability_report"] = self.vulnerability_report.to_dict()
        return result
