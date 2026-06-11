"""
IoT Device Signature Database.

Maps manufacturer/vendor substrings and hostname patterns to device type
classifications. Confidence values range from 0.0 to 1.0.

This database is informed by real-world scan data and common IoT device
manufacturers. Extend by adding entries to VENDOR_SIGNATURES or
HOSTNAME_PATTERNS.
"""

from .models import DeviceType


# ---------------------------------------------------------------------------
# Vendor Signatures
# Maps lowercase vendor/manufacturer substrings → (DeviceType, confidence)
# ---------------------------------------------------------------------------

VENDOR_SIGNATURES: dict[str, tuple[DeviceType, float]] = {
    # Networking Equipment
    "netgear": (DeviceType.ROUTER, 0.7),
    "tp-link": (DeviceType.ROUTER, 0.7),
    "tp-link systems": (DeviceType.ROUTER, 0.7),
    "cisco": (DeviceType.ROUTER, 0.7),
    "cisco systems": (DeviceType.ROUTER, 0.7),
    "linksys": (DeviceType.ROUTER, 0.7),
    "asus": (DeviceType.ROUTER, 0.6),
    "ubiquiti": (DeviceType.ROUTER, 0.7),
    "ubiquiti networks": (DeviceType.ROUTER, 0.7),
    "d-link": (DeviceType.ROUTER, 0.7),
    "arris": (DeviceType.ROUTER, 0.7),
    "motorola": (DeviceType.ROUTER, 0.5),
    "alpha networks": (DeviceType.ROUTER, 0.7),
    "azurewave": (DeviceType.ROUTER, 0.6),
    "azurewave technology": (DeviceType.ROUTER, 0.6),
    "nokia": (DeviceType.ROUTER, 0.5),
    "nokia solutions": (DeviceType.ROUTER, 0.6),
    "huawei": (DeviceType.ROUTER, 0.6),
    "zyxel": (DeviceType.ROUTER, 0.7),
    "mikrotik": (DeviceType.ROUTER, 0.8),

    # Cameras & Security
    "hikvision": (DeviceType.CAMERA, 0.9),
    "dahua": (DeviceType.CAMERA, 0.9),
    "axis communications": (DeviceType.CAMERA, 0.9),
    "wyze": (DeviceType.CAMERA, 0.8),
    "ring": (DeviceType.CAMERA, 0.8),
    "arlo": (DeviceType.CAMERA, 0.8),
    "reolink": (DeviceType.CAMERA, 0.8),
    "amcrest": (DeviceType.CAMERA, 0.8),
    "nest labs": (DeviceType.CAMERA, 0.8),

    # Printers
    "hewlett packard": (DeviceType.PRINTER, 0.8),
    "hp inc": (DeviceType.PRINTER, 0.8),
    "hp": (DeviceType.PRINTER, 0.7),
    "canon": (DeviceType.PRINTER, 0.7),
    "epson": (DeviceType.PRINTER, 0.7),
    "brother": (DeviceType.PRINTER, 0.7),
    "lexmark": (DeviceType.PRINTER, 0.8),
    "xerox": (DeviceType.PRINTER, 0.8),

    # Smart Home - Google
    "google": (DeviceType.SMART_SPEAKER, 0.7),
    "google inc": (DeviceType.SMART_SPEAKER, 0.7),

    # Smart Home - Amazon
    "amazon": (DeviceType.SMART_SPEAKER, 0.7),
    "amazon technologies": (DeviceType.SMART_SPEAKER, 0.7),

    # Smart Home - Apple
    "apple": (DeviceType.MEDIA_PLAYER, 0.5),
    "apple inc": (DeviceType.MEDIA_PLAYER, 0.5),

    # Smart Home - General
    "philips": (DeviceType.SMART_HOME_HUB, 0.5),
    "signify": (DeviceType.SMART_HOME_HUB, 0.6),
    "sonos": (DeviceType.SMART_SPEAKER, 0.9),
    "ecobee": (DeviceType.SMART_HOME_HUB, 0.8),
    "lutron": (DeviceType.SMART_HOME_HUB, 0.8),
    "wemo": (DeviceType.SMART_HOME_HUB, 0.7),
    "belkin": (DeviceType.SMART_HOME_HUB, 0.5),
    "tuya": (DeviceType.SMART_HOME_HUB, 0.6),
    "smartthings": (DeviceType.SMART_HOME_HUB, 0.8),
    "hubitat": (DeviceType.SMART_HOME_HUB, 0.9),

    # Smart Appliances
    "chamberlain": (DeviceType.SMART_APPLIANCE, 0.8),
    "the chamberlain group": (DeviceType.SMART_APPLIANCE, 0.8),
    "seongji": (DeviceType.SMART_APPLIANCE, 0.8),
    "seongji industry": (DeviceType.SMART_APPLIANCE, 0.8),
    "irobot": (DeviceType.SMART_APPLIANCE, 0.9),
    "roborock": (DeviceType.SMART_APPLIANCE, 0.9),
    "ecovacs": (DeviceType.SMART_APPLIANCE, 0.9),
    "lg electronics": (DeviceType.SMART_APPLIANCE, 0.4),
    "whirlpool": (DeviceType.SMART_APPLIANCE, 0.7),

    # Phones / Mobile
    "samsung": (DeviceType.PHONE, 0.5),
    "samsung electronics": (DeviceType.PHONE, 0.5),
    "oneplus": (DeviceType.PHONE, 0.7),
    "xiaomi": (DeviceType.PHONE, 0.5),

    # Media Players
    "roku": (DeviceType.MEDIA_PLAYER, 0.9),
    "nvidia": (DeviceType.MEDIA_PLAYER, 0.6),

    # NAS / Storage
    "synology": (DeviceType.NETWORK_STORAGE, 0.9),
    "qnap": (DeviceType.NETWORK_STORAGE, 0.9),
    "western digital": (DeviceType.NETWORK_STORAGE, 0.6),
    "seagate": (DeviceType.NETWORK_STORAGE, 0.6),

    # Computers
    "dell": (DeviceType.COMPUTER, 0.6),
    "lenovo": (DeviceType.COMPUTER, 0.6),
    "intel": (DeviceType.COMPUTER, 0.5),
    "raspberry pi": (DeviceType.COMPUTER, 0.8),
}


# ---------------------------------------------------------------------------
# Hostname Patterns
# Maps regex patterns → (DeviceType, confidence)
# Patterns are matched case-insensitively against the device hostname.
# ---------------------------------------------------------------------------

HOSTNAME_PATTERNS: dict[str, tuple[DeviceType, float]] = {
    # Cameras
    r"(?i)nest[-_ ]?cam": (DeviceType.CAMERA, 0.95),
    r"(?i)cam|ipcam|camera|dvr|nvr": (DeviceType.CAMERA, 0.85),
    r"(?i)hikvision|dahua|amcrest|reolink": (DeviceType.CAMERA, 0.9),

    # Routers
    r"(?i)router|gateway|modem|access[-_ ]?point|ap\d": (DeviceType.ROUTER, 0.85),
    r"(?i)netgear|tp-?link|linksys|asus[-_ ]?rt|ubiquiti": (DeviceType.ROUTER, 0.8),

    # Printers
    r"(?i)printer|laserjet|deskjet|officejet|inkjet|mfp": (DeviceType.PRINTER, 0.9),
    r"(?i)epson|canon[-_ ]?(mx|ts|tr)|brother[-_ ]?(hl|mfc)": (DeviceType.PRINTER, 0.85),
    r"(?i)hp[0-9a-f]{6}": (DeviceType.PRINTER, 0.7),

    # Smart Speakers
    r"(?i)google[-_ ]?home|nest[-_ ]?(mini|hub|audio)": (DeviceType.SMART_SPEAKER, 0.9),
    r"(?i)echo|alexa|fire[-_ ]?tv": (DeviceType.SMART_SPEAKER, 0.85),
    r"(?i)sonos": (DeviceType.SMART_SPEAKER, 0.9),
    r"(?i)homepod": (DeviceType.SMART_SPEAKER, 0.9),

    # Smart Displays
    r"(?i)nest[-_ ]?hub[-_ ]?max|echo[-_ ]?show": (DeviceType.SMART_DISPLAY, 0.9),

    # Smart Appliances
    r"(?i)vacuum|roomba|roborock|deebot": (DeviceType.SMART_APPLIANCE, 0.9),
    r"(?i)thermostat|ecobee|nest[-_ ]?thermostat": (DeviceType.SMART_APPLIANCE, 0.9),
    r"(?i)garage|chamberlain|myq": (DeviceType.SMART_APPLIANCE, 0.85),
    r"(?i)washer|dryer|fridge|dishwasher|oven": (DeviceType.SMART_APPLIANCE, 0.85),

    # Smart Home Hubs
    r"(?i)hub|bridge|smartthings|hue[-_ ]?bridge|hubitat": (DeviceType.SMART_HOME_HUB, 0.7),

    # Media Players
    r"(?i)roku|chromecast|apple[-_ ]?tv|fire[-_ ]?stick|shield": (DeviceType.MEDIA_PLAYER, 0.9),

    # Phones
    r"(?i)iphone|android|galaxy|pixel|oneplus": (DeviceType.PHONE, 0.8),

    # Computers
    r"(?i)desktop|laptop|workstation|macbook|imac": (DeviceType.COMPUTER, 0.8),
    r"(?i)raspberry[-_ ]?pi|rpi": (DeviceType.COMPUTER, 0.9),

    # NAS
    r"(?i)nas|synology|qnap|diskstation": (DeviceType.NETWORK_STORAGE, 0.9),
}


# ---------------------------------------------------------------------------
# HTTP Server Signatures
# Maps Server header substrings → (DeviceType, confidence)
# ---------------------------------------------------------------------------

HTTP_SERVER_SIGNATURES: dict[str, tuple[DeviceType, float]] = {
    "hikvision": (DeviceType.CAMERA, 0.95),
    "dahua": (DeviceType.CAMERA, 0.95),
    "boa/": (DeviceType.CAMERA, 0.7),  # Common IP camera web server
    "goahead": (DeviceType.CAMERA, 0.7),  # Common IP camera web server
    "thttpd": (DeviceType.CAMERA, 0.5),
    "hp-chaiserver": (DeviceType.PRINTER, 0.9),
    "hp http server": (DeviceType.PRINTER, 0.9),
    "epson_linux": (DeviceType.PRINTER, 0.9),
    "canon http server": (DeviceType.PRINTER, 0.9),
    "router": (DeviceType.ROUTER, 0.6),
    "mini_httpd": (DeviceType.ROUTER, 0.5),
    "micro_httpd": (DeviceType.ROUTER, 0.5),
    "lighttpd": (DeviceType.ROUTER, 0.4),
    "synology": (DeviceType.NETWORK_STORAGE, 0.9),
}


# ---------------------------------------------------------------------------
# Port Profile Heuristics
# Maps sets of open ports to likely device types
# ---------------------------------------------------------------------------

PORT_DEVICE_HINTS: dict[int, tuple[DeviceType, float]] = {
    554: (DeviceType.CAMERA, 0.7),      # RTSP - likely camera
    8554: (DeviceType.CAMERA, 0.7),     # RTSP alt
    631: (DeviceType.PRINTER, 0.8),     # IPP
    9100: (DeviceType.PRINTER, 0.8),    # JetDirect
    515: (DeviceType.PRINTER, 0.7),     # LPD
    1883: (DeviceType.SMART_HOME_HUB, 0.5),  # MQTT
    8883: (DeviceType.SMART_HOME_HUB, 0.5),  # MQTT/TLS
    5683: (DeviceType.SMART_HOME_HUB, 0.5),  # CoAP
    49152: (DeviceType.SMART_HOME_HUB, 0.4),  # UPnP
    8008: (DeviceType.MEDIA_PLAYER, 0.5),     # Chromecast
    8009: (DeviceType.MEDIA_PLAYER, 0.5),     # Chromecast
    8443: (DeviceType.ROUTER, 0.4),           # HTTPS admin
    548: (DeviceType.NETWORK_STORAGE, 0.7),   # AFP
    5000: (DeviceType.NETWORK_STORAGE, 0.5),  # Synology
    5001: (DeviceType.NETWORK_STORAGE, 0.5),  # Synology HTTPS
    139: (DeviceType.COMPUTER, 0.4),          # NetBIOS
    445: (DeviceType.COMPUTER, 0.4),          # SMB
    3389: (DeviceType.COMPUTER, 0.6),         # RDP
}
