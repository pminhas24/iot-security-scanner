"""
Unified CLI Entry Point for the IoT Security Scanner.

Orchestrates the full scan pipeline:
  1. Network discovery (host detection)
  2. Port scanning & service detection       (--scan-ports / -p)
  3. Device fingerprinting & classification  (--fingerprint)
  4. Vulnerability detection                 (--vuln-check)
  5. Database storage                        (--save-db)
  6. Web dashboard                           (--web / -w)

All original network_discovery.py CLI flags are preserved for
backward compatibility.
"""

import argparse
import json
import logging
import sys
import time

from scanner.network_discovery import (
    NetworkDiscovery,
    NmapNotFoundError,
    NetworkScanError,
    setup_logging,
)
from scanner.port_scanner import PortScanner, PortScanError
from scanner.models import DeviceScanResult


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser with all flags across phases."""
    parser = argparse.ArgumentParser(
        description="IoT Security Scanner - Discover, scan, and assess IoT devices",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  %(prog)s -r 192.168.1.0/24                    # Host discovery only
  %(prog)s -r 192.168.1.0/24 -p                 # Discovery + port scan
  %(prog)s -t 192.168.1.87 -p -v                # Scan single device, verbose
  %(prog)s -r 192.168.1.0/24 -p --fingerprint   # Discovery + ports + fingerprint
  %(prog)s -q -p --vuln-check                   # Quick scan + ports + vulns
  %(prog)s --web                                 # Start web dashboard
""",
    )

    # === Original flags (backward compatible) ===
    parser.add_argument(
        "-r", "--range",
        help="Network range to scan in CIDR notation (e.g., 192.168.1.0/24)",
    )
    parser.add_argument(
        "-t", "--target",
        help="Specific IP address to scan",
    )
    parser.add_argument(
        "-q", "--quick",
        action="store_true",
        help="Perform quick scan with port detection (uses NetworkDiscovery.quick_scan)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose/debug output",
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file path for JSON results",
    )
    parser.add_argument(
        "--log-file",
        help="Log file path",
    )

    # === Phase 2: Port Scanning ===
    phase2 = parser.add_argument_group("Port Scanning (Phase 2)")
    phase2.add_argument(
        "-p", "--scan-ports",
        action="store_true",
        help="Enable detailed port scanning and service detection",
    )
    phase2.add_argument(
        "--ports",
        help="Comma-separated list of ports to scan (default: 21,22,23,80,443,554,8080,8443,9000)",
    )

    # === Phase 3: Fingerprinting (placeholder for next phase) ===
    phase3 = parser.add_argument_group("Device Fingerprinting (Phase 3)")
    phase3.add_argument(
        "--fingerprint",
        action="store_true",
        help="Enable device fingerprinting and classification",
    )

    # === Phase 4: Vulnerability Detection (placeholder) ===
    phase4 = parser.add_argument_group("Vulnerability Detection (Phase 4)")
    phase4.add_argument(
        "--vuln-check",
        action="store_true",
        help="Enable vulnerability detection (default credentials, dangerous ports)",
    )
    phase4.add_argument(
        "--dry-run",
        action="store_true",
        help="Report what vulnerability checks would run without connecting",
    )

    # === Phase 5: Database (placeholder) ===
    phase5 = parser.add_argument_group("Database Storage (Phase 5)")
    phase5.add_argument(
        "--save-db",
        action="store_true",
        help="Save scan results to database",
    )
    phase5.add_argument(
        "--db-type",
        choices=["sqlite", "postgresql"],
        default="sqlite",
        help="Database backend (default: sqlite)",
    )
    phase5.add_argument(
        "--db-path",
        default="iot_scanner.db",
        help="SQLite database file path (default: iot_scanner.db)",
    )
    phase5.add_argument("--db-host", default="localhost", help="PostgreSQL host")
    phase5.add_argument("--db-port", type=int, default=5432, help="PostgreSQL port")
    phase5.add_argument("--db-name", default="iot_scanner", help="PostgreSQL database name")
    phase5.add_argument("--db-user", default="iot_scanner", help="PostgreSQL user")
    phase5.add_argument("--db-password", default="", help="PostgreSQL password")

    # === Phase 6: Web Dashboard (placeholder) ===
    phase6 = parser.add_argument_group("Web Dashboard (Phase 6)")
    phase6.add_argument(
        "-w", "--web",
        action="store_true",
        help="Start the web dashboard server",
    )
    phase6.add_argument(
        "--web-port",
        type=int,
        default=5000,
        help="Web dashboard port (default: 5000)",
    )

    return parser


def main() -> None:
    """Main entry point for the IoT Security Scanner CLI."""
    parser = build_parser()
    args = parser.parse_args()

    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    setup_logging(level=log_level, log_file=args.log_file)

    logger = logging.getLogger(__name__)

    # --- Phase 6: Web Dashboard (early exit) ---
    if args.web:
        try:
            from api.app import create_app

            db_config = _build_db_config(args)
            app = create_app(db_config=db_config)
            print(f"\nStarting IoT Security Scanner Web Dashboard on port {args.web_port}...")
            print(f"Open http://localhost:{args.web_port}/ in your browser\n")
            app.run(host="0.0.0.0", port=args.web_port, debug=args.verbose)
        except ImportError:
            print("Error: Web dashboard module not yet available (Phase 6).")
            sys.exit(1)
        return

    # --- Scan Pipeline ---
    try:
        scan_start = time.time()

        # Step 1: Network Discovery
        print("\n" + "=" * 60)
        print("  IoT Security Scanner")
        print("=" * 60)

        nd = NetworkDiscovery()

        if args.target:
            print(f"\n[*] Scanning target device: {args.target}")
            devices = [nd.scan_device(args.target)]
        elif args.quick:
            print("\n[*] Running quick scan...")
            devices = nd.quick_scan(args.range)
        else:
            print("\n[*] Discovering hosts on network...")
            devices = nd.discover_hosts(args.range)

        print(f"[+] Found {len(devices)} device(s)")

        # Step 2: Port Scanning (Phase 2)
        results: list[DeviceScanResult] = []
        if args.scan_ports and devices:
            print(f"\n[*] Scanning ports on {len(devices)} device(s)...")
            port_scanner = PortScanner(scanner=nd.scanner)
            custom_ports = None
            if args.ports:
                custom_ports = [int(p.strip()) for p in args.ports.split(",")]

            for i, device in enumerate(devices, 1):
                print(f"  [{i}/{len(devices)}] Scanning {device.ip_address}...")
                try:
                    port_result = port_scanner.scan_device(
                        device.ip_address, ports=custom_ports
                    )
                    results.append(DeviceScanResult(
                        device=device, port_scan=port_result
                    ))
                except PortScanError as e:
                    logger.warning(f"Port scan failed for {device.ip_address}: {e}")
                    results.append(DeviceScanResult(device=device))

            total_open = sum(
                len(r.port_scan.open_ports) for r in results if r.port_scan
            )
            total_dangerous = sum(
                len(r.port_scan.dangerous_ports) for r in results if r.port_scan
            )
            print(f"[+] Port scan complete: {total_open} open ports, "
                  f"{total_dangerous} dangerous")
        else:
            results = [DeviceScanResult(device=d) for d in devices]

        # Step 3: Device Fingerprinting (Phase 3)
        if args.fingerprint and results:
            try:
                from scanner.device_fingerprinting import DeviceFingerprinter

                print(f"\n[*] Fingerprinting {len(results)} device(s)...")
                fingerprinter = DeviceFingerprinter()
                for r in results:
                    fp = fingerprinter.fingerprint(
                        r.device,
                        port_scan=r.port_scan,
                    )
                    r.fingerprint = fp
                print("[+] Fingerprinting complete")
            except ImportError:
                print("[!] Fingerprinting module not yet available (Phase 3)")

        # Step 4: Vulnerability Detection (Phase 4)
        if args.vuln_check and results:
            try:
                from scanner.vulnerability_checker import VulnerabilityChecker

                print(f"\n[*] Running vulnerability checks on {len(results)} device(s)...")
                vuln_checker = VulnerabilityChecker(dry_run=args.dry_run)
                for r in results:
                    report = vuln_checker.check(
                        r.device,
                        port_scan=r.port_scan,
                        fingerprint=r.fingerprint,
                    )
                    r.vulnerability_report = report
                print("[+] Vulnerability checks complete")
            except ImportError:
                print("[!] Vulnerability checker not yet available (Phase 4)")

        scan_duration = time.time() - scan_start

        # Step 5: Database Storage (Phase 5)
        if args.save_db and results:
            try:
                from database.db_manager import DatabaseManager

                db_config = _build_db_config(args)
                print(f"\n[*] Saving results to {args.db_type} database...")
                with DatabaseManager(**db_config) as db:
                    db.initialize_schema()
                    network_range = args.range or nd.get_network_range()
                    scan_type = "quick" if args.quick else (
                        "targeted" if args.target else "discovery"
                    )
                    scan_id = db.save_scan(
                        network_range=network_range,
                        scan_type=scan_type,
                        results=results,
                        duration_sec=scan_duration,
                    )
                    print(f"[+] Results saved (scan_id: {scan_id})")
            except ImportError:
                print("[!] Database module not yet available (Phase 5)")

        # --- Output ---
        _print_results(results)

        if args.output:
            _save_json(results, args.output)

        # Summary
        print(f"\n{'=' * 60}")
        print(f"  Scan completed in {scan_duration:.1f}s")
        print(f"  Devices found: {len(results)}")
        if args.scan_ports:
            total_open = sum(
                len(r.port_scan.open_ports) for r in results if r.port_scan
            )
            total_dangerous = sum(
                len(r.port_scan.dangerous_ports) for r in results if r.port_scan
            )
            print(f"  Open ports: {total_open}")
            print(f"  Dangerous ports: {total_dangerous}")
        if args.vuln_check:
            critical = sum(
                1 for r in results
                if r.vulnerability_report
                and r.vulnerability_report.risk_level == "critical"
            )
            high = sum(
                1 for r in results
                if r.vulnerability_report
                and r.vulnerability_report.risk_level == "high"
            )
            if critical or high:
                print(f"  Critical risk devices: {critical}")
                print(f"  High risk devices: {high}")
        print(f"{'=' * 60}\n")

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


def _print_results(results: list[DeviceScanResult]) -> None:
    """Pretty-print scan results to stdout."""
    print(f"\n{'─' * 60}")
    print(f"  SCAN RESULTS ({len(results)} devices)")
    print(f"{'─' * 60}")

    for r in results:
        d = r.device
        print(f"\n  IP: {d.ip_address}")
        print(f"  Hostname: {d.hostname or 'N/A'}")
        print(f"  MAC: {d.mac_address or 'N/A'}")
        print(f"  Vendor: {d.vendor or 'N/A'}")
        print(f"  State: {d.state}")

        # Fingerprint info
        if r.fingerprint:
            fp = r.fingerprint
            print(f"  Device Type: {fp.device_type}")
            if fp.manufacturer:
                print(f"  Manufacturer: {fp.manufacturer}")
            if fp.model:
                print(f"  Model: {fp.model}")

        # Port scan info
        if r.port_scan and r.port_scan.open_ports:
            print(f"  Open Ports ({len(r.port_scan.open_ports)}):")
            for p in r.port_scan.open_ports:
                danger_flag = " [DANGEROUS]" if p.is_dangerous else ""
                svc = f"{p.product} {p.version}".strip() or p.service
                print(f"    {p.port}/tcp  {p.service:<12} {svc}{danger_flag}")
            if r.port_scan.dangerous_ports:
                print(f"  *** {len(r.port_scan.dangerous_ports)} dangerous port(s) detected ***")

        # Vulnerability info
        if r.vulnerability_report:
            vr = r.vulnerability_report
            print(f"  Risk Score: {vr.risk_score}/100 ({vr.risk_level.upper()})")
            if vr.vulnerabilities:
                print(f"  Vulnerabilities ({len(vr.vulnerabilities)}):")
                for v in vr.vulnerabilities:
                    print(f"    [{v.severity.value.upper()}] {v.vuln_type}: {v.details}")

        print()


def _save_json(results: list[DeviceScanResult], output_path: str) -> None:
    """Write results to a JSON file."""
    data = [r.to_dict() for r in results]
    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[+] Results saved to {output_path}")


def _build_db_config(args) -> dict:
    """Build database configuration dict from CLI args."""
    if args.db_type == "sqlite":
        return {
            "db_type": "sqlite",
            "db_path": args.db_path,
        }
    else:
        return {
            "db_type": "postgresql",
            "host": args.db_host,
            "port": args.db_port,
            "database": args.db_name,
            "user": args.db_user,
            "password": args.db_password,
        }


if __name__ == "__main__":
    main()
