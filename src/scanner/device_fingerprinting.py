"""
Device Fingerprinting Module for IoT Security Scanner.

Classifies discovered devices by type (router, camera, printer,
smart_device, etc.) using multiple identification strategies:

1. MAC vendor + hostname pattern matching against signature DB
2. HTTP header probing (Server header, HTML title)
3. UPnP/SSDP discovery (device description XML)
4. Open port profile heuristic
"""

import logging
import re
import socket
import xml.etree.ElementTree as ET
from typing import Optional

import requests

from .models import DeviceFingerprint, DeviceType, PortScanResult
from .network_discovery import DiscoveredDevice
from .signatures import (
    VENDOR_SIGNATURES,
    HOSTNAME_PATTERNS,
    HTTP_SERVER_SIGNATURES,
    PORT_DEVICE_HINTS,
)

logger = logging.getLogger(__name__)


class DeviceFingerprinter:
    """
    Fingerprints and classifies discovered IoT devices.

    Uses a layered classification strategy, combining vendor data,
    hostname patterns, active probing, and port profile heuristics
    to identify device types and extract model/firmware information.
    """

    def __init__(self, custom_signatures: Optional[dict] = None):
        """
        Initialize the DeviceFingerprinter.

        Args:
            custom_signatures: Optional dict of vendor_substring →
                (DeviceType, confidence) to merge with defaults.
        """
        self.vendor_signatures = dict(VENDOR_SIGNATURES)
        if custom_signatures:
            self.vendor_signatures.update(custom_signatures)

    def fingerprint(
        self,
        device: DiscoveredDevice,
        port_scan: Optional[PortScanResult] = None,
    ) -> DeviceFingerprint:
        """
        Classify a single device using all available information.

        Strategy (in priority order):
        1. Hostname pattern matching (highest confidence when matched)
        2. MAC vendor signature lookup
        3. HTTP header probing (if port 80/8080 is open)
        4. UPnP/SSDP probing (if port 49152 is open)
        5. Port profile heuristic fallback

        Args:
            device: DiscoveredDevice from network discovery.
            port_scan: Optional PortScanResult from port scanning phase.

        Returns:
            DeviceFingerprint with classification and extracted info.
        """
        logger.debug(f"Fingerprinting {device.ip_address} "
                      f"(vendor={device.vendor}, hostname={device.hostname})")

        best_type = DeviceType.UNKNOWN
        best_confidence = 0.0
        manufacturer = device.vendor or ""
        model = ""
        firmware = ""

        # --- Strategy 1: Hostname pattern matching ---
        if device.hostname:
            result = self._match_hostname_pattern(device.hostname)
            if result and result[1] > best_confidence:
                best_type, best_confidence = result
                logger.debug(f"  Hostname match: {best_type.value} "
                              f"(confidence={best_confidence})")

        # --- Strategy 2: Vendor signature lookup ---
        if device.vendor:
            result = self._match_vendor_signature(device.vendor)
            if result and result[1] > best_confidence:
                best_type, best_confidence = result
                logger.debug(f"  Vendor match: {best_type.value} "
                              f"(confidence={best_confidence})")

        # --- Strategy 3: HTTP header probing ---
        if port_scan:
            http_ports = [
                p.port for p in port_scan.open_ports
                if p.service in ("http", "http-alt", "http-proxy")
                or p.port in (80, 8080, 8000, 8888)
            ]
            for port in http_ports:
                try:
                    http_info = self._probe_http_headers(
                        device.ip_address, port
                    )
                    if http_info.get("device_type"):
                        dt = http_info["device_type"]
                        conf = http_info.get("confidence", 0.6)
                        if conf > best_confidence:
                            best_type = dt
                            best_confidence = conf
                            logger.debug(f"  HTTP match: {best_type.value} "
                                          f"(confidence={best_confidence})")
                    if http_info.get("model"):
                        model = http_info["model"]
                    if http_info.get("firmware"):
                        firmware = http_info["firmware"]
                    if http_info.get("manufacturer"):
                        manufacturer = http_info["manufacturer"]
                    # Stop after first successful probe
                    if model or best_confidence > 0.7:
                        break
                except Exception as e:
                    logger.debug(f"  HTTP probe failed on port {port}: {e}")

        # --- Strategy 4: UPnP probing ---
        if port_scan:
            upnp_ports = [
                p.port for p in port_scan.open_ports
                if p.port in (49152, 1900, 5000) or p.service == "upnp"
            ]
            if upnp_ports:
                try:
                    upnp_info = self._probe_upnp(device.ip_address)
                    if upnp_info.get("manufacturer"):
                        manufacturer = upnp_info["manufacturer"]
                    if upnp_info.get("model_name"):
                        model = upnp_info["model_name"]
                    if upnp_info.get("firmware"):
                        firmware = upnp_info["firmware"]
                    # Re-classify based on UPnP device type
                    if upnp_info.get("device_type_str"):
                        upnp_dt = self._classify_upnp_type(
                            upnp_info["device_type_str"]
                        )
                        if upnp_dt != DeviceType.UNKNOWN:
                            upnp_conf = 0.85
                            if upnp_conf > best_confidence:
                                best_type = upnp_dt
                                best_confidence = upnp_conf
                except Exception as e:
                    logger.debug(f"  UPnP probe failed: {e}")

        # --- Strategy 5: Port profile heuristic ---
        if best_type == DeviceType.UNKNOWN and port_scan:
            result = self._classify_by_port_profile(port_scan)
            if result and result[1] > best_confidence:
                best_type, best_confidence = result
                logger.debug(f"  Port profile match: {best_type.value} "
                              f"(confidence={best_confidence})")

        # Use vendor as manufacturer fallback
        if not manufacturer and device.vendor:
            manufacturer = device.vendor

        fingerprint = DeviceFingerprint(
            ip_address=device.ip_address,
            device_type=best_type.value,
            manufacturer=manufacturer,
            model=model,
            firmware_version=firmware,
            classification_confidence=round(best_confidence, 2),
        )

        logger.info(
            f"Fingerprinted {device.ip_address}: "
            f"type={fingerprint.device_type}, "
            f"manufacturer={fingerprint.manufacturer}, "
            f"model={fingerprint.model or 'N/A'}, "
            f"confidence={fingerprint.classification_confidence}"
        )
        return fingerprint

    def fingerprint_batch(
        self,
        devices: list[DiscoveredDevice],
        port_scans: Optional[dict[str, PortScanResult]] = None,
    ) -> list[DeviceFingerprint]:
        """
        Fingerprint multiple devices.

        Args:
            devices: List of discovered devices.
            port_scans: Optional dict mapping IP → PortScanResult.

        Returns:
            List of DeviceFingerprint objects.
        """
        results = []
        for device in devices:
            ps = port_scans.get(device.ip_address) if port_scans else None
            try:
                fp = self.fingerprint(device, port_scan=ps)
                results.append(fp)
            except Exception as e:
                logger.error(
                    f"Fingerprinting failed for {device.ip_address}: {e}"
                )
                results.append(DeviceFingerprint(ip_address=device.ip_address))
        return results

    # -----------------------------------------------------------------------
    # Private matching methods
    # -----------------------------------------------------------------------

    def _match_vendor_signature(
        self, vendor: str
    ) -> Optional[tuple[DeviceType, float]]:
        """
        Look up vendor string in the signature database.

        Performs case-insensitive substring matching, returning the
        longest match for specificity.

        Args:
            vendor: Vendor string from MAC lookup.

        Returns:
            (DeviceType, confidence) or None.
        """
        vendor_lower = vendor.lower().strip()
        best_match = None
        best_key_len = 0

        for key, value in self.vendor_signatures.items():
            if key in vendor_lower and len(key) > best_key_len:
                best_match = value
                best_key_len = len(key)

        return best_match

    def _match_hostname_pattern(
        self, hostname: str
    ) -> Optional[tuple[DeviceType, float]]:
        """
        Match hostname against regex patterns in the signature DB.

        Returns the highest-confidence match.

        Args:
            hostname: Device hostname.

        Returns:
            (DeviceType, confidence) or None.
        """
        best_match = None
        best_confidence = 0.0

        for pattern, (device_type, confidence) in HOSTNAME_PATTERNS.items():
            if re.search(pattern, hostname):
                if confidence > best_confidence:
                    best_match = (device_type, confidence)
                    best_confidence = confidence

        return best_match

    def _probe_http_headers(
        self,
        ip_address: str,
        port: int = 80,
        timeout: int = 5,
    ) -> dict:
        """
        Send HTTP GET and extract identifying information.

        Extracts: Server header, HTML <title>, model/firmware strings
        from common IoT device web interfaces.

        Args:
            ip_address: Target IP.
            port: HTTP port.
            timeout: Request timeout in seconds.

        Returns:
            Dict with keys: server, title, device_type, confidence,
            manufacturer, model, firmware (any found).
        """
        info: dict = {}
        url = f"http://{ip_address}:{port}/"

        try:
            response = requests.get(
                url,
                timeout=timeout,
                allow_redirects=True,
                verify=False,
                headers={"User-Agent": "IoT-Scanner/1.0"},
            )

            # Parse Server header
            server = response.headers.get("Server", "").lower()
            info["server"] = server

            if server:
                for sig, (dt, conf) in HTTP_SERVER_SIGNATURES.items():
                    if sig in server:
                        info["device_type"] = dt
                        info["confidence"] = conf
                        break

            # Parse X-Powered-By
            powered_by = response.headers.get("X-Powered-By", "")
            if powered_by:
                info["powered_by"] = powered_by

            # Parse HTML title
            html = response.text[:4096]  # Only first 4KB
            title_match = re.search(
                r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL
            )
            if title_match:
                title = title_match.group(1).strip()
                info["title"] = title
                # Try to extract model from title
                model_info = self._extract_model_from_title(title)
                info.update(model_info)

            # Check for WWW-Authenticate header (often reveals device type)
            www_auth = response.headers.get("WWW-Authenticate", "")
            if www_auth:
                info["www_authenticate"] = www_auth
                # Many IoT devices put their name in the realm
                realm_match = re.search(r'realm="([^"]+)"', www_auth)
                if realm_match:
                    realm = realm_match.group(1)
                    if not info.get("model"):
                        info["model"] = realm

        except requests.exceptions.RequestException as e:
            logger.debug(f"HTTP probe failed for {ip_address}:{port}: {e}")

        return info

    def _probe_upnp(
        self,
        ip_address: str,
        timeout: int = 3,
    ) -> dict:
        """
        Send UPnP M-SEARCH and parse the device description XML.

        Args:
            ip_address: Target IP address.
            timeout: Socket timeout in seconds.

        Returns:
            Dict with keys: friendly_name, manufacturer, model_name,
            model_number, device_type_str, firmware (any found).
        """
        info: dict = {}

        # Step 1: M-SEARCH for device location
        msearch = (
            "M-SEARCH * HTTP/1.1\r\n"
            f"HOST: {ip_address}:1900\r\n"
            "MAN: \"ssdp:discover\"\r\n"
            "MX: 2\r\n"
            "ST: upnp:rootdevice\r\n"
            "\r\n"
        )

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(msearch.encode(), (ip_address, 1900))

            data, _ = sock.recvfrom(4096)
            response_text = data.decode("utf-8", errors="replace")
            sock.close()

            # Extract LOCATION header
            location_match = re.search(
                r"LOCATION:\s*(http://\S+)", response_text, re.IGNORECASE
            )
            if not location_match:
                return info

            location_url = location_match.group(1)

            # Step 2: Fetch and parse device description XML
            desc_response = requests.get(location_url, timeout=timeout)
            if desc_response.status_code != 200:
                return info

            root = ET.fromstring(desc_response.text)
            # Handle XML namespace
            ns = {"upnp": "urn:schemas-upnp-org:device-1-0"}

            device_elem = root.find(".//upnp:device", ns)
            if device_elem is None:
                # Try without namespace
                device_elem = root.find(".//device")

            if device_elem is not None:
                info["friendly_name"] = self._get_xml_text(
                    device_elem, "friendlyName", ns
                )
                info["manufacturer"] = self._get_xml_text(
                    device_elem, "manufacturer", ns
                )
                info["model_name"] = self._get_xml_text(
                    device_elem, "modelName", ns
                )
                info["model_number"] = self._get_xml_text(
                    device_elem, "modelNumber", ns
                )
                info["device_type_str"] = self._get_xml_text(
                    device_elem, "deviceType", ns
                )
                # Firmware might be in modelDescription or serialNumber
                info["firmware"] = self._get_xml_text(
                    device_elem, "modelDescription", ns
                )

                # Combine model_name and model_number
                if info.get("model_name") and info.get("model_number"):
                    info["model_name"] = (
                        f"{info['model_name']} {info['model_number']}"
                    )

        except (socket.timeout, socket.error) as e:
            logger.debug(f"UPnP probe failed for {ip_address}: {e}")
        except Exception as e:
            logger.debug(f"UPnP probe error for {ip_address}: {e}")

        return info

    def _classify_by_port_profile(
        self,
        port_scan: PortScanResult,
    ) -> Optional[tuple[DeviceType, float]]:
        """
        Heuristic classification based on open port patterns.

        Args:
            port_scan: PortScanResult with open ports.

        Returns:
            (DeviceType, confidence) or None.
        """
        if not port_scan.open_ports:
            return None

        # Count votes from port hints
        type_scores: dict[DeviceType, float] = {}
        for port_info in port_scan.open_ports:
            if port_info.port in PORT_DEVICE_HINTS:
                dt, conf = PORT_DEVICE_HINTS[port_info.port]
                type_scores[dt] = max(type_scores.get(dt, 0), conf)

            # Also check service names from nmap
            service = port_info.service.lower()
            if "rtsp" in service:
                type_scores[DeviceType.CAMERA] = max(
                    type_scores.get(DeviceType.CAMERA, 0), 0.7
                )
            elif "ipp" in service or "printer" in service:
                type_scores[DeviceType.PRINTER] = max(
                    type_scores.get(DeviceType.PRINTER, 0), 0.8
                )
            elif "mqtt" in service:
                type_scores[DeviceType.SMART_HOME_HUB] = max(
                    type_scores.get(DeviceType.SMART_HOME_HUB, 0), 0.5
                )

        if not type_scores:
            return None

        best_type = max(type_scores, key=type_scores.get)
        return (best_type, type_scores[best_type])

    def _classify_upnp_type(self, upnp_type_str: str) -> DeviceType:
        """
        Classify based on UPnP device type string.

        Args:
            upnp_type_str: UPnP deviceType value (URN format).

        Returns:
            Matched DeviceType.
        """
        type_lower = upnp_type_str.lower()

        if "mediarenderer" in type_lower:
            return DeviceType.MEDIA_PLAYER
        elif "mediaserver" in type_lower:
            return DeviceType.NETWORK_STORAGE
        elif "internetgateway" in type_lower or "wandevice" in type_lower:
            return DeviceType.ROUTER
        elif "printer" in type_lower:
            return DeviceType.PRINTER
        elif "camera" in type_lower or "digitalSecurityCamera" in type_lower:
            return DeviceType.CAMERA
        elif "basic" in type_lower:
            return DeviceType.UNKNOWN

        return DeviceType.UNKNOWN

    def _extract_model_from_title(self, title: str) -> dict:
        """
        Try to extract model/manufacturer info from an HTML title.

        Many IoT device web interfaces put their model name in the
        page title (e.g., "NETGEAR R7000", "HP LaserJet Pro M404n").

        Args:
            title: HTML page title.

        Returns:
            Dict with 'model' and/or 'manufacturer' if found.
        """
        info: dict = {}

        # Common patterns: "Manufacturer Model" or "Model - Manufacturer"
        # Look for model numbers (alphanumeric patterns)
        model_match = re.search(
            r"([A-Z][A-Za-z-]+)\s+([A-Z0-9][\w-]{2,})", title
        )
        if model_match:
            info["manufacturer"] = model_match.group(1)
            info["model"] = model_match.group(2)

        return info

    @staticmethod
    def _get_xml_text(
        element: ET.Element,
        tag: str,
        namespaces: dict,
    ) -> str:
        """Get text content of a child XML element, with namespace fallback."""
        # Try with namespace
        for ns_prefix, ns_uri in namespaces.items():
            child = element.find(f"{{{ns_uri}}}{tag}")
            if child is not None and child.text:
                return child.text.strip()

        # Try without namespace
        child = element.find(tag)
        if child is not None and child.text:
            return child.text.strip()

        return ""
