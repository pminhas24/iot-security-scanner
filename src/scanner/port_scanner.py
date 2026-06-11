"""
Port Scanner Module for IoT Security Scanner.

Scans devices for open ports, identifies running services,
and flags dangerous/unnecessary ports with severity levels.
"""

import logging
from datetime import datetime, timezone
from typing import Optional

import nmap

from .models import PortInfo, PortScanResult, Severity

logger = logging.getLogger(__name__)


class PortScanError(Exception):
    """Raised when a port scan fails."""
    pass


class PortScanner:
    """
    Scans IoT devices for open ports and identifies services.

    Uses Nmap for service version detection and classifies ports
    as dangerous based on a built-in threat database.

    Attributes:
        DEFAULT_PORTS: Default list of IoT-relevant ports to scan.
        DANGEROUS_PORTS: Mapping of port numbers to danger info.
    """

    DEFAULT_PORTS: list[int] = [21, 22, 23, 80, 443, 554, 8080, 8443, 9000]

    DANGEROUS_PORTS: dict[int, tuple[str, Severity]] = {
        21: (
            "FTP - unencrypted file transfer protocol, often allows anonymous access",
            Severity.HIGH,
        ),
        23: (
            "Telnet - unencrypted remote shell, credentials sent in plaintext",
            Severity.CRITICAL,
        ),
        80: (
            "HTTP - unencrypted web interface, credentials may be exposed",
            Severity.MEDIUM,
        ),
        554: (
            "RTSP - camera streaming protocol, often unauthenticated",
            Severity.HIGH,
        ),
        8080: (
            "HTTP-Alt - often an admin or debug interface left exposed",
            Severity.MEDIUM,
        ),
        9000: (
            "IoT management port, frequently misconfigured",
            Severity.MEDIUM,
        ),
    }

    def __init__(
        self,
        nmap_path: Optional[str] = None,
        timeout: int = 300,
        scanner: Optional[nmap.PortScanner] = None,
    ):
        """
        Initialize the PortScanner.

        Args:
            nmap_path: Optional path to nmap executable.
            timeout: Scan timeout in seconds (default: 300).
            scanner: Optional pre-initialized nmap.PortScanner instance.
                     Pass this to share a scanner with NetworkDiscovery
                     and avoid redundant nmap verification.
        """
        self.timeout = timeout
        if scanner is not None:
            self._scanner = scanner
        else:
            try:
                if nmap_path:
                    self._scanner = nmap.PortScanner(
                        nmap_search_path=(nmap_path,)
                    )
                else:
                    self._scanner = nmap.PortScanner()
            except nmap.PortScannerError as e:
                raise PortScanError(f"Failed to initialize nmap scanner: {e}")

    def scan_device(
        self,
        ip_address: str,
        ports: Optional[list[int]] = None,
    ) -> PortScanResult:
        """
        Scan a single device for open ports and identify services.

        Performs a service version detection scan (-sV). Attempts a
        SYN scan first (-sS, faster, requires admin/root), falling
        back to a TCP connect scan (-sT) if SYN fails.

        Args:
            ip_address: Target IP address to scan.
            ports: List of port numbers to scan. Defaults to DEFAULT_PORTS.

        Returns:
            PortScanResult containing all discovered ports and danger flags.

        Raises:
            PortScanError: If the scan fails entirely.
        """
        if ports is None:
            ports = self.DEFAULT_PORTS

        port_arg = ",".join(str(p) for p in ports)
        timestamp = datetime.now(timezone.utc).isoformat()

        logger.info(f"Starting port scan on {ip_address} (ports: {port_arg})")

        # Try SYN scan first (faster, requires elevated privileges)
        scan_success = False
        try:
            self._scanner.scan(
                hosts=ip_address,
                arguments=f"-sS -sV -T4 -p{port_arg}",
                timeout=self.timeout,
            )
            scan_success = True
            logger.debug(f"SYN scan completed for {ip_address}")
        except nmap.PortScannerError as e:
            logger.warning(
                f"SYN scan failed for {ip_address} (may need admin): {e}"
            )

        # Fall back to connect scan
        if not scan_success:
            try:
                self._scanner.scan(
                    hosts=ip_address,
                    arguments=f"-sT -sV -T4 -p{port_arg}",
                    timeout=self.timeout,
                )
                scan_success = True
                logger.debug(f"Connect scan completed for {ip_address}")
            except nmap.PortScannerError as e:
                error_msg = f"Port scan failed for {ip_address}: {e}"
                logger.error(error_msg)
                raise PortScanError(error_msg)
            except Exception as e:
                error_msg = f"Unexpected error scanning {ip_address}: {e}"
                logger.error(error_msg)
                raise PortScanError(error_msg)

        # Parse results
        open_ports: list[PortInfo] = []
        dangerous_ports: list[PortInfo] = []

        if ip_address in self._scanner.all_hosts():
            host_data = self._scanner[ip_address]
            if "tcp" in host_data:
                for port_num, port_data in host_data["tcp"].items():
                    if port_data.get("state") == "open":
                        port_info = self._classify_port(
                            port=port_num,
                            service=port_data.get("name", "unknown"),
                            product=port_data.get("product", ""),
                            version=port_data.get("version", ""),
                        )
                        open_ports.append(port_info)
                        if port_info.is_dangerous:
                            dangerous_ports.append(port_info)

        result = PortScanResult(
            ip_address=ip_address,
            open_ports=open_ports,
            dangerous_ports=dangerous_ports,
            scan_timestamp=timestamp,
        )

        logger.info(
            f"Port scan complete for {ip_address}: "
            f"{len(open_ports)} open, {len(dangerous_ports)} dangerous"
        )
        return result

    def scan_devices(
        self,
        ip_addresses: list[str],
        ports: Optional[list[int]] = None,
    ) -> list[PortScanResult]:
        """
        Scan multiple devices for open ports.

        Args:
            ip_addresses: List of IP addresses to scan.
            ports: List of port numbers. Defaults to DEFAULT_PORTS.

        Returns:
            List of PortScanResult, one per device.
        """
        results = []
        total = len(ip_addresses)
        for i, ip in enumerate(ip_addresses, 1):
            logger.info(f"Scanning device {i}/{total}: {ip}")
            try:
                result = self.scan_device(ip, ports)
                results.append(result)
            except PortScanError as e:
                logger.error(f"Skipping {ip}: {e}")
                # Return an empty result for failed scans
                results.append(PortScanResult(
                    ip_address=ip,
                    scan_timestamp=datetime.now(timezone.utc).isoformat(),
                ))
        return results

    def _classify_port(
        self,
        port: int,
        service: str,
        product: str,
        version: str,
    ) -> PortInfo:
        """
        Build a PortInfo and flag if the port is dangerous.

        Args:
            port: Port number.
            service: Service name from nmap (e.g., "ssh", "http").
            product: Product string from nmap (e.g., "OpenSSH").
            version: Version string from nmap (e.g., "8.9p1").

        Returns:
            PortInfo with danger classification applied.
        """
        is_dangerous = False
        danger_reason = ""
        severity = Severity.INFO

        if port in self.DANGEROUS_PORTS:
            reason, sev = self.DANGEROUS_PORTS[port]
            is_dangerous = True
            danger_reason = reason
            severity = sev
        elif service in ("telnet",):
            # Telnet on a non-standard port is still dangerous
            is_dangerous = True
            danger_reason = (
                f"Telnet service on non-standard port {port} - "
                "credentials sent in plaintext"
            )
            severity = Severity.CRITICAL
        elif service in ("ftp",):
            # FTP on a non-standard port
            is_dangerous = True
            danger_reason = (
                f"FTP service on non-standard port {port} - "
                "unencrypted file transfer"
            )
            severity = Severity.HIGH

        return PortInfo(
            port=port,
            protocol="tcp",
            service=service,
            product=product,
            version=version,
            is_dangerous=is_dangerous,
            danger_reason=danger_reason,
            severity=severity,
        )

    @staticmethod
    def get_severity_for_port(port: int) -> Severity:
        """
        Get the severity level for a known dangerous port.

        Args:
            port: Port number to check.

        Returns:
            Severity level, or INFO if the port is not classified as dangerous.
        """
        if port in PortScanner.DANGEROUS_PORTS:
            return PortScanner.DANGEROUS_PORTS[port][1]
        return Severity.INFO
