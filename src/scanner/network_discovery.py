"""
Network Discovery Module for IoT Security Scanner

This module provides functionality to discover devices on the local network
using Nmap. It identifies hosts, open ports, and basic device information.
"""

import logging
import socket
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Optional

try:
    import nmap
except ImportError:
    print("Error: python-nmap is not installed. Run: pip install python-nmap")
    sys.exit(1)


# Configure module logger
logger = logging.getLogger(__name__)


@dataclass
class DiscoveredDevice:
    """Represents a discovered network device."""
    ip_address: str
    hostname: str = ""
    mac_address: str = ""
    vendor: str = ""
    state: str = "unknown"
    open_ports: list = field(default_factory=list)
    os_guess: str = ""

    def to_dict(self) -> dict:
        """Convert device info to dictionary."""
        return {
            "ip_address": self.ip_address,
            "hostname": self.hostname,
            "mac_address": self.mac_address,
            "vendor": self.vendor,
            "state": self.state,
            "open_ports": self.open_ports,
            "os_guess": self.os_guess
        }


class NmapNotFoundError(Exception):
    """Raised when Nmap is not installed or not found in PATH."""
    pass


class NetworkScanError(Exception):
    """Raised when a network scan fails."""
    pass


class NetworkDiscovery:
    """
    Network Discovery scanner using Nmap.

    This class provides methods to discover devices on a local network,
    identify open ports, and gather basic device information.

    Attributes:
        nmap_path: Optional path to nmap executable
        timeout: Scan timeout in seconds
    """

    # Common IoT ports to scan
    IOT_PORTS = [
        22,     # SSH
        23,     # Telnet
        80,     # HTTP
        443,    # HTTPS
        554,    # RTSP (cameras)
        1883,   # MQTT
        5683,   # CoAP
        8080,   # HTTP Alt
        8443,   # HTTPS Alt
        8883,   # MQTT over SSL
        9000,   # Various IoT
        49152,  # UPnP
    ]

    def __init__(self, nmap_path: Optional[str] = None, timeout: int = 300):
        """
        Initialize the NetworkDiscovery scanner.

        Args:
            nmap_path: Optional path to nmap executable. If None, uses PATH.
            timeout: Scan timeout in seconds (default: 300)

        Raises:
            NmapNotFoundError: If Nmap is not installed or accessible
        """
        self.timeout = timeout
        self.nmap_path = nmap_path
        self._scanner: Optional[nmap.PortScanner] = None

        self._verify_nmap_installation()
        self._init_scanner()

    @property
    def scanner(self) -> nmap.PortScanner:
        """Public accessor for the underlying nmap scanner instance."""
        return self._scanner

    def _verify_nmap_installation(self) -> None:
        """
        Verify that Nmap is installed and accessible.

        Raises:
            NmapNotFoundError: If Nmap is not found
        """
        try:
            nmap_cmd = self.nmap_path or "nmap"
            result = subprocess.run(
                [nmap_cmd, "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                version_line = result.stdout.split('\n')[0]
                logger.info(f"Nmap found: {version_line}")
            else:
                raise NmapNotFoundError("Nmap returned non-zero exit code")
        except FileNotFoundError:
            error_msg = (
                "Nmap is not installed or not in PATH. "
                "Please install Nmap from https://nmap.org/download.html"
            )
            logger.error(error_msg)
            raise NmapNotFoundError(error_msg)
        except subprocess.TimeoutExpired:
            error_msg = "Nmap version check timed out"
            logger.error(error_msg)
            raise NmapNotFoundError(error_msg)

    def _init_scanner(self) -> None:
        """Initialize the Nmap PortScanner instance."""
        try:
            if self.nmap_path:
                self._scanner = nmap.PortScanner(nmap_search_path=(self.nmap_path,))
            else:
                self._scanner = nmap.PortScanner()
            logger.debug("Nmap PortScanner initialized successfully")
        except nmap.PortScannerError as e:
            logger.error(f"Failed to initialize Nmap scanner: {e}")
            raise NmapNotFoundError(f"Failed to initialize Nmap scanner: {e}")

    def get_local_ip(self) -> str:
        """
        Get the local IP address of this machine.

        Returns:
            Local IP address as string

        Raises:
            NetworkScanError: If unable to determine local IP
        """
        try:
            # Create a socket to determine local IP
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                # Doesn't actually connect, just determines route
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                logger.debug(f"Local IP detected: {local_ip}")
                return local_ip
        except socket.error as e:
            error_msg = f"Failed to determine local IP address: {e}"
            logger.error(error_msg)
            raise NetworkScanError(error_msg)

    def get_network_range(self) -> str:
        """
        Get the local network range in CIDR notation.

        Returns:
            Network range string (e.g., "192.168.1.0/24")

        Raises:
            NetworkScanError: If unable to determine network range
        """
        try:
            local_ip = self.get_local_ip()
            # Assume /24 subnet (most common for home/small office networks)
            ip_parts = local_ip.split('.')
            network_range = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
            logger.info(f"Network range determined: {network_range}")
            return network_range
        except Exception as e:
            error_msg = f"Failed to determine network range: {e}"
            logger.error(error_msg)
            raise NetworkScanError(error_msg)

    def discover_hosts(self, network_range: Optional[str] = None) -> list[DiscoveredDevice]:
        """
        Discover active hosts on the network using ping scan.

        Args:
            network_range: Network range to scan (e.g., "192.168.1.0/24").
                          If None, auto-detects local network.

        Returns:
            List of DiscoveredDevice objects for active hosts

        Raises:
            NetworkScanError: If scan fails
        """
        if network_range is None:
            network_range = self.get_network_range()

        logger.info(f"Starting host discovery on {network_range}")

        try:
            # -sn: Ping scan (no port scan)
            # -T4: Aggressive timing
            self._scanner.scan(
                hosts=network_range,
                arguments="-sn -T4",
                timeout=self.timeout
            )
        except nmap.PortScannerError as e:
            error_msg = f"Host discovery scan failed: {e}"
            logger.error(error_msg)
            raise NetworkScanError(error_msg)
        except Exception as e:
            error_msg = f"Unexpected error during host discovery: {e}"
            logger.error(error_msg)
            raise NetworkScanError(error_msg)

        devices = []
        for host in self._scanner.all_hosts():
            device = self._parse_host_info(host)
            devices.append(device)
            logger.debug(f"Discovered host: {device.ip_address} ({device.hostname})")

        logger.info(f"Host discovery complete. Found {len(devices)} devices.")
        return devices

    def scan_device(
        self,
        ip_address: str,
        ports: Optional[list[int]] = None,
        detect_os: bool = False
    ) -> DiscoveredDevice:
        """
        Perform detailed scan of a specific device.

        Args:
            ip_address: IP address of device to scan
            ports: List of ports to scan. If None, uses IOT_PORTS
            detect_os: Whether to attempt OS detection (requires admin/root)

        Returns:
            DiscoveredDevice with scan results

        Raises:
            NetworkScanError: If scan fails
        """
        if ports is None:
            ports = self.IOT_PORTS

        port_arg = ",".join(str(p) for p in ports)

        # Build scan arguments
        scan_args = f"-sV -T4 -p{port_arg}"
        if detect_os:
            scan_args += " -O"

        logger.info(f"Scanning device {ip_address} on ports: {port_arg}")

        try:
            self._scanner.scan(
                hosts=ip_address,
                arguments=scan_args,
                timeout=self.timeout
            )
        except nmap.PortScannerError as e:
            error_msg = f"Device scan failed for {ip_address}: {e}"
            logger.error(error_msg)
            raise NetworkScanError(error_msg)
        except Exception as e:
            error_msg = f"Unexpected error scanning {ip_address}: {e}"
            logger.error(error_msg)
            raise NetworkScanError(error_msg)

        if ip_address not in self._scanner.all_hosts():
            logger.warning(f"Host {ip_address} not found in scan results")
            return DiscoveredDevice(ip_address=ip_address, state="down")

        return self._parse_host_info(ip_address, include_ports=True)

    def quick_scan(self, network_range: Optional[str] = None) -> list[DiscoveredDevice]:
        """
        Perform a quick scan: discover hosts and scan common IoT ports.

        Args:
            network_range: Network range to scan. If None, auto-detects.

        Returns:
            List of DiscoveredDevice objects with port information

        Raises:
            NetworkScanError: If scan fails
        """
        if network_range is None:
            network_range = self.get_network_range()

        port_arg = ",".join(str(p) for p in self.IOT_PORTS)

        logger.info(f"Starting quick scan on {network_range}")

        try:
            # -sS: TCP SYN scan (faster, requires admin on some systems)
            # -sV: Version detection
            # -T4: Aggressive timing
            self._scanner.scan(
                hosts=network_range,
                arguments=f"-sS -sV -T4 -p{port_arg}",
                timeout=self.timeout
            )
        except nmap.PortScannerError as e:
            # Fall back to connect scan if SYN scan fails (requires admin)
            logger.warning(f"SYN scan failed, trying connect scan: {e}")
            try:
                self._scanner.scan(
                    hosts=network_range,
                    arguments=f"-sT -sV -T4 -p{port_arg}",
                    timeout=self.timeout
                )
            except nmap.PortScannerError as e2:
                error_msg = f"Quick scan failed: {e2}"
                logger.error(error_msg)
                raise NetworkScanError(error_msg)

        devices = []
        for host in self._scanner.all_hosts():
            device = self._parse_host_info(host, include_ports=True)
            devices.append(device)

        logger.info(f"Quick scan complete. Found {len(devices)} devices.")
        return devices

    def _parse_host_info(self, host: str, include_ports: bool = False) -> DiscoveredDevice:
        """
        Parse host information from scan results.

        Args:
            host: IP address of the host
            include_ports: Whether to include port information

        Returns:
            DiscoveredDevice with parsed information
        """
        host_info = self._scanner[host]

        # Get hostname
        hostname = ""
        if "hostnames" in host_info and host_info["hostnames"]:
            hostname = host_info["hostnames"][0].get("name", "")

        # Get MAC address and vendor
        mac_address = ""
        vendor = ""
        if "addresses" in host_info:
            mac_address = host_info["addresses"].get("mac", "")
        if "vendor" in host_info and mac_address:
            vendor = host_info["vendor"].get(mac_address, "")

        # Get state
        state = host_info.get("status", {}).get("state", "unknown")

        # Get open ports
        open_ports = []
        if include_ports and "tcp" in host_info:
            for port, port_info in host_info["tcp"].items():
                if port_info.get("state") == "open":
                    open_ports.append({
                        "port": port,
                        "service": port_info.get("name", "unknown"),
                        "product": port_info.get("product", ""),
                        "version": port_info.get("version", "")
                    })

        # Get OS guess
        os_guess = ""
        if "osmatch" in host_info and host_info["osmatch"]:
            os_guess = host_info["osmatch"][0].get("name", "")

        return DiscoveredDevice(
            ip_address=host,
            hostname=hostname,
            mac_address=mac_address,
            vendor=vendor,
            state=state,
            open_ports=open_ports,
            os_guess=os_guess
        )

    def get_scan_stats(self) -> dict:
        """
        Get statistics from the last scan.

        Returns:
            Dictionary with scan statistics
        """
        if self._scanner is None:
            return {}

        try:
            return {
                "command_line": self._scanner.command_line(),
                "scan_info": self._scanner.scaninfo(),
                "hosts_scanned": len(self._scanner.all_hosts())
            }
        except Exception:
            return {}


def setup_logging(level: int = logging.INFO, log_file: Optional[str] = None) -> None:
    """
    Configure logging for the network discovery module.

    Args:
        level: Logging level (default: INFO)
        log_file: Optional path to log file
    """
    log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    handlers = [logging.StreamHandler()]
    if log_file:
        handlers.append(logging.FileHandler(log_file))

    logging.basicConfig(
        level=level,
        format=log_format,
        handlers=handlers
    )


# Example usage and CLI interface
if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser(description="IoT Network Discovery Scanner")
    parser.add_argument(
        "-r", "--range",
        help="Network range to scan (e.g., 192.168.1.0/24)"
    )
    parser.add_argument(
        "-t", "--target",
        help="Specific IP address to scan"
    )
    parser.add_argument(
        "-q", "--quick",
        action="store_true",
        help="Perform quick scan with port detection"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file for JSON results"
    )
    parser.add_argument(
        "--log-file",
        help="Log file path"
    )

    args = parser.parse_args()

    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    setup_logging(level=log_level, log_file=args.log_file)

    try:
        scanner = NetworkDiscovery()

        if args.target:
            # Scan specific device
            print(f"\nScanning device: {args.target}")
            device = scanner.scan_device(args.target)
            devices = [device]
        elif args.quick:
            # Quick scan with ports
            print("\nPerforming quick scan...")
            devices = scanner.quick_scan(args.range)
        else:
            # Host discovery only
            print("\nDiscovering hosts...")
            devices = scanner.discover_hosts(args.range)

        # Display results
        print(f"\nFound {len(devices)} device(s):\n")
        for device in devices:
            print(f"  IP: {device.ip_address}")
            print(f"  Hostname: {device.hostname or 'N/A'}")
            print(f"  MAC: {device.mac_address or 'N/A'}")
            print(f"  Vendor: {device.vendor or 'N/A'}")
            print(f"  State: {device.state}")
            if device.open_ports:
                print("  Open Ports:")
                for port in device.open_ports:
                    print(f"    - {port['port']}/{port['service']} "
                          f"({port['product']} {port['version']})")
            print()

        # Save to file if requested
        if args.output:
            results = [d.to_dict() for d in devices]
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"Results saved to {args.output}")

        # Print scan stats
        stats = scanner.get_scan_stats()
        if stats:
            print(f"Scan command: {stats.get('command_line', 'N/A')}")

    except NmapNotFoundError as e:
        print(f"\nError: {e}")
        print("\nPlease install Nmap:")
        print("  Windows: Download from https://nmap.org/download.html")
        print("  Make sure to add Nmap to your system PATH")
        sys.exit(1)
    except NetworkScanError as e:
        print(f"\nScan Error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\nScan cancelled by user.")
        sys.exit(0)
