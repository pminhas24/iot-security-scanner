"""
Flask Web Dashboard for IoT Security Scanner.

Provides REST API endpoints and HTML dashboard for viewing
scan results, device details, and vulnerability reports.
"""

import json
import logging
import threading
import time
from typing import Optional

from flask import Flask, render_template, jsonify, request, abort, Response, stream_with_context
from werkzeug.exceptions import HTTPException

logger = logging.getLogger(__name__)


def create_app(db_config: Optional[dict] = None) -> Flask:
    """
    Flask application factory.

    Args:
        db_config: Database connection parameters dict.
            For SQLite: {"db_type": "sqlite", "db_path": "iot_scanner.db"}
            For PostgreSQL: {"db_type": "postgresql", "host": ..., ...}

    Returns:
        Configured Flask app.
    """
    import sys
    import os

    # Add src/ to path so imports work
    src_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if src_dir not in sys.path:
        sys.path.insert(0, src_dir)

    app = Flask(
        __name__,
        template_folder=os.path.join(src_dir, "frontend", "templates"),
        static_folder=os.path.join(src_dir, "frontend", "static"),
    )

    app.config["DB_CONFIG"] = db_config or {
        "db_type": "sqlite",
        "db_path": "iot_scanner.db",
    }

    # Track running scans
    app.config["SCAN_STATUS"] = {
        "running": False,
        "progress": "",
        "last_scan_id": None,
    }

    def get_db():
        """Get a DatabaseManager instance."""
        from database.db_manager import DatabaseManager
        db = DatabaseManager(**app.config["DB_CONFIG"])
        db.connect()
        return db

    # -------------------------------------------------------------------
    # HTML Routes
    # -------------------------------------------------------------------

    @app.route("/")
    def index():
        """Dashboard home page."""
        try:
            db = get_db()
            devices = db.get_all_devices()
            risk_summary = db.get_risk_summary()
            scan_history = db.get_scan_history(limit=5)
            db.disconnect()
            return render_template(
                "index.html",
                devices=devices,
                risk_summary=risk_summary,
                scan_history=scan_history,
            )
        except Exception as e:
            logger.error(f"Dashboard error: {e}")
            return render_template(
                "index.html",
                devices=[],
                risk_summary={
                    "total_devices": 0, "critical": 0, "high": 0,
                    "medium": 0, "low": 0, "avg_risk_score": 0,
                    "most_vulnerable": None,
                },
                scan_history=[],
                error=str(e),
            )

    @app.route("/device/<ip_address>")
    def device_detail_page(ip_address: str):
        """Device detail HTML page."""
        try:
            db = get_db()
            device = db.get_device_by_ip(ip_address)
            db.disconnect()
            if not device:
                abort(404)
            return render_template("device_detail.html", device=device)
        except HTTPException:
            raise  # Let HTTP exceptions (404, etc.) propagate
        except Exception as e:
            logger.error(f"Device detail error: {e}")
            abort(500)

    # -------------------------------------------------------------------
    # API Routes
    # -------------------------------------------------------------------

    @app.route("/api/devices")
    def api_devices():
        """GET /api/devices - List all devices from most recent scan."""
        try:
            db = get_db()
            devices = db.get_all_devices()
            db.disconnect()
            return jsonify({"devices": devices, "count": len(devices)})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/devices/<ip_address>")
    def api_device_detail(ip_address: str):
        """GET /api/devices/<ip> - Device detail with ports and vulns."""
        try:
            db = get_db()
            device = db.get_device_by_ip(ip_address)
            db.disconnect()
            if not device:
                return jsonify({"error": f"Device {ip_address} not found"}), 404
            return jsonify(device)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/vulnerabilities")
    def api_vulnerabilities():
        """GET /api/vulnerabilities - All vulnerabilities, optional ?severity= filter."""
        try:
            db = get_db()
            severity = request.args.get("severity")
            vulns = db.get_vulnerabilities(severity=severity)
            db.disconnect()
            return jsonify({"vulnerabilities": vulns, "count": len(vulns)})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/scan/status")
    def api_scan_status():
        """GET /api/scan/status - Check if a scan is running."""
        return jsonify(app.config["SCAN_STATUS"])

    @app.route("/api/scan/start", methods=["POST"])
    def api_start_scan():
        """
        POST /api/scan/start - Trigger a new scan.

        Request body (JSON):
            network_range: optional CIDR range
            scan_type: "discovery" | "quick" | "full"

        custom_ports and dry_run are read from the saved settings
        (api.config) at scan start.

        Returns immediately; scan runs in background thread.
        """
        if app.config["SCAN_STATUS"]["running"]:
            return jsonify({"error": "A scan is already running"}), 409

        data = request.get_json(silent=True) or {}
        network_range = data.get("network_range")
        scan_type = data.get("scan_type", "full")

        from api import config as settings_config
        saved = settings_config.load()
        custom_ports = None
        raw_ports = str(saved.get("custom_ports") or "").strip()
        if raw_ports:
            try:
                custom_ports = [
                    int(p.strip()) for p in raw_ports.split(",") if p.strip()
                ]
            except ValueError:
                logger.warning(
                    f"Ignoring invalid custom_ports setting: {raw_ports!r}"
                )
        dry_run = bool(saved.get("dry_run", False))

        def run_scan():
            app.config["SCAN_STATUS"]["running"] = True
            app.config["SCAN_STATUS"]["progress"] = "Starting scan..."
            try:
                from scanner.network_discovery import NetworkDiscovery
                from scanner.port_scanner import PortScanner
                from scanner.device_fingerprinting import DeviceFingerprinter
                from scanner.vulnerability_checker import VulnerabilityChecker
                from scanner.models import DeviceScanResult
                from database.db_manager import DatabaseManager

                scan_start = time.time()

                nd = NetworkDiscovery()
                app.config["SCAN_STATUS"]["progress"] = "Discovering hosts..."

                if scan_type == "quick":
                    devices = nd.quick_scan(network_range)
                else:
                    devices = nd.discover_hosts(network_range)

                results = []
                total = len(devices)

                if scan_type in ("quick", "full"):
                    ps = PortScanner(scanner=nd.scanner)
                    fp_engine = DeviceFingerprinter()
                    vc = VulnerabilityChecker(dry_run=dry_run)

                    for i, device in enumerate(devices, 1):
                        app.config["SCAN_STATUS"]["progress"] = (
                            f"Scanning device {i}/{total}: {device.ip_address}"
                        )
                        try:
                            port_result = ps.scan_device(
                                device.ip_address, ports=custom_ports
                            )
                            fingerprint = fp_engine.fingerprint(device, port_result)
                            vuln_report = vc.check(device, port_result, fingerprint)
                            results.append(DeviceScanResult(
                                device=device,
                                port_scan=port_result,
                                fingerprint=fingerprint,
                                vulnerability_report=vuln_report,
                            ))
                        except Exception as e:
                            logger.error(f"Scan error for {device.ip_address}: {e}")
                            results.append(DeviceScanResult(device=device))
                else:
                    results = [DeviceScanResult(device=d) for d in devices]

                duration = time.time() - scan_start
                app.config["SCAN_STATUS"]["progress"] = "Saving results..."

                db = DatabaseManager(**app.config["DB_CONFIG"])
                db.connect()
                db.initialize_schema()
                nr = network_range or nd.get_network_range()
                scan_id = db.save_scan(nr, scan_type, results, duration)
                db.disconnect()

                app.config["SCAN_STATUS"]["last_scan_id"] = scan_id
                app.config["SCAN_STATUS"]["progress"] = (
                    f"Complete: {len(results)} devices scanned in {duration:.1f}s"
                )

            except Exception as e:
                logger.error(f"Background scan failed: {e}")
                app.config["SCAN_STATUS"]["progress"] = f"Error: {e}"
            finally:
                app.config["SCAN_STATUS"]["running"] = False

        thread = threading.Thread(target=run_scan, daemon=True)
        thread.start()

        return jsonify({
            "status": "started",
            "scan_type": scan_type,
            "network_range": network_range or "auto-detect",
        })

    @app.route("/api/risk-summary")
    def api_risk_summary():
        """GET /api/risk-summary - Risk statistics for dashboard."""
        try:
            db = get_db()
            summary = db.get_risk_summary()
            db.disconnect()
            return jsonify(summary)
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/settings", methods=["GET"])
    def api_settings_get():
        """GET /api/settings - Return current scan settings."""
        from api import config
        return jsonify(config.load())

    @app.route("/api/settings", methods=["POST"])
    def api_settings_save():
        """POST /api/settings - Persist scan settings."""
        from api import config
        data = request.get_json(silent=True) or {}
        try:
            config.save(data)
        except Exception as e:
            logger.error(f"Failed to save settings: {e}")
            return jsonify({"error": str(e)}), 500
        return jsonify({"status": "saved"})

    @app.route("/api/network/detect")
    def api_network_detect():
        """GET /api/network/detect - Auto-detect local subnet."""
        try:
            from scanner.network_discovery import NetworkDiscovery
            subnet = NetworkDiscovery().get_network_range()
            return jsonify({"subnet": subnet})
        except Exception as e:
            return jsonify({"subnet": "", "error": str(e)})

    @app.route("/api/scan/stream")
    def api_scan_stream():
        """GET /api/scan/stream - SSE stream of scan progress."""
        def _generate():
            last_progress = None
            scan_started = False
            while True:
                status = dict(app.config["SCAN_STATUS"])
                progress = status["progress"]
                running = status["running"]

                if running:
                    scan_started = True

                if progress != last_progress:
                    yield f"data: {json.dumps({'progress': progress, 'running': running})}\n\n"
                    last_progress = progress

                if scan_started and not running and last_progress is not None:
                    yield "event: scan_complete\ndata: {\"done\": true}\n\n"
                    return

                time.sleep(0.5)

        return Response(
            stream_with_context(_generate()),
            mimetype="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    return app
