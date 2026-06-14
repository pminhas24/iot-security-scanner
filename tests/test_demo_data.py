"""
Regression tests for dev_run.py demo data taxonomy.

The seeded demo devices must use only canonical DeviceType values — the
same strings the real fingerprinting pipeline emits (fingerprint.device_type
= DeviceType(...).value). If a demo device uses a type the pipeline can never
produce, the dashboard demonstrates an impossible state and EXPECTED_PORTS /
signature lookups silently miss. These tests guard against that drift.
"""

import os
import sys
import types

REPO_ROOT = os.path.join(os.path.dirname(__file__), '..')
SRC = os.path.join(REPO_ROOT, 'src')
sys.path.insert(0, SRC)
sys.path.insert(0, REPO_ROOT)

# Register a lightweight 'scanner' package stub *before* importing
# scanner.models. The real scanner/__init__.py eagerly imports the whole
# pipeline (requests, paramiko, scapy, nmap) just to re-export classes; none
# of that is needed to read the DeviceType enum, and forcing those heavy
# runtime deps onto a pure data test would make it fail to even collect in a
# minimal environment. models.py and its only dependency (network_discovery)
# are stdlib-only, so the submodule imports cleanly on its own.
if 'scanner' not in sys.modules:
    _pkg = types.ModuleType('scanner')
    _pkg.__path__ = [os.path.join(SRC, 'scanner')]
    sys.modules['scanner'] = _pkg

from scanner.models import DeviceType  # noqa: E402
import dev_run  # noqa: E402


VALID_DEVICE_TYPES = {dt.value for dt in DeviceType}


def test_all_demo_device_types_are_canonical():
    """Every demo device_type must be a real DeviceType enum value."""
    for device in dev_run.DEMO_DEVICES:
        assert device["device_type"] in VALID_DEVICE_TYPES, (
            f"{device['hostname']} uses device_type "
            f"{device['device_type']!r}, which is not a DeviceType value. "
            f"Valid values: {sorted(VALID_DEVICE_TYPES)}"
        )


def test_demo_covers_expected_canonical_types():
    """The demo set should exercise the canonical types we expect to show."""
    seen = {d["device_type"] for d in dev_run.DEMO_DEVICES}
    expected = {
        "router", "camera", "media_player",
        "printer", "computer", "smart_appliance",
    }
    assert expected <= seen, (
        f"Demo data missing expected types: {sorted(expected - seen)}"
    )
