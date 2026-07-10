#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Discover nearby classic Bluetooth devices via inquiry scan."""

from __future__ import annotations

import re
import shutil
import subprocess
from typing import Dict

from kittysploit import *


class Module(Auxiliary):
    __info__ = {
        "name": "Bluetooth Classic Scanner",
        "description": (
            "Discover nearby classic Bluetooth devices using hcitool or bluetoothctl "
            "inquiry scans."
        ),
        "author": ["KittySploit Team"],
        "tags": ["scanner", "bluetooth", "classic", "wireless", "discovery"],
        "references": [
            "https://attack.mitre.org/techniques/T1016/",
        ],
        "attack": {
            "tactics": ["TA0007", "Discovery"],
            "techniques": ["T1016"],
            "prerequisites": [
                "Host Bluetooth adapter with classic BR/EDR support",
                "hcitool or bluetoothctl available on operator host",
            ],
            "detections": [
                "Bluetooth inquiry scan from operator workstation",
            ],
            "artifacts": [
                "Local Bluetooth scan logs",
            ],
        },
    'agent': {
        'risk': 'active',
        'effects': ['wireless_probe'],
        'expected_requests': 1,
        'reversible': True,
        'approval_required': False,
        'produces': ['endpoints', 'tech_hints'],
        'cost': 1.0,
        'noise': 0.5,
        'value': 1.0,
        'requires':         {'min_endpoints': 0,
         'min_params': 0,
         'tech_hints_any': [],
         'tech_hints_all': [],
         'specializations_any': [],
         'risk_signals_any': [],
         'auth_session': False,
         'capabilities_any': [],
         'capabilities_all': [],
         'confidence_min': {},
         'confidence_min_any': {},
         'endpoint_pattern_any': [],
         'param_any': [],
         'api_surface_ready': False},
        'chain':         {'produces_capabilities': [],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    timeout = OptInteger(12, "Inquiry scan duration in seconds", required=False)
    hci = OptString("hci0", "Bluetooth HCI device", required=False)
    method = OptChoice(
        "auto",
        "Scan backend: auto, hcitool, or bluetoothctl",
        required=False,
        choices=["auto", "hcitool", "bluetoothctl"],
    )

    def check(self):
        method = self._resolve_method()
        if method:
            return True
        print_error(
            "No supported classic Bluetooth scanner found. "
            "Install bluez package (hcitool and/or bluetoothctl)."
        )
        return False

    def run(self):
        timeout = max(3, int(self.timeout or 12))
        hci = str(self.hci or "hci0").strip()
        method = self._resolve_method()

        print_info(f"Classic Bluetooth scan via {method} for {timeout}s on {hci}")
        print_info("=" * 72)

        try:
            if method == "hcitool":
                devices = self._scan_hcitool(hci, timeout)
            else:
                devices = self._scan_bluetoothctl(timeout)
        except Exception as exc:
            print_error(f"Bluetooth scan failed: {exc}")
            print_info("Ensure Bluetooth is enabled and not blocked (rfkill unblock bluetooth)")
            return False

        print_info("=" * 72)
        if not devices:
            print_warning("No classic Bluetooth devices discovered")
            return False

        print_success(f"Discovered {len(devices)} device(s)")
        for address in sorted(devices):
            print_info(f"  {devices[address]:32} {address}")
        return True

    def _resolve_method(self) -> str:
        choice = str(self.method or "auto").strip().lower()
        has_hcitool = bool(shutil.which("hcitool"))
        has_bluetoothctl = bool(shutil.which("bluetoothctl"))

        if choice == "hcitool" and has_hcitool:
            return "hcitool"
        if choice == "bluetoothctl" and has_bluetoothctl:
            return "bluetoothctl"
        if choice == "auto":
            if has_hcitool:
                return "hcitool"
            if has_bluetoothctl:
                return "bluetoothctl"
        return ""

    def _scan_hcitool(self, hci: str, timeout: int) -> Dict[str, str]:
        proc = subprocess.run(
            ["hcitool", "-i", hci, "scan", "--flush"],
            capture_output=True,
            text=True,
            timeout=timeout + 5,
            check=False,
        )
        if proc.returncode != 0 and not proc.stdout:
            raise RuntimeError((proc.stderr or proc.stdout or "hcitool scan failed").strip())

        devices: Dict[str, str] = {}
        for line in proc.stdout.splitlines():
            match = re.match(r"^([0-9A-Fa-f:]{17})\s+(.+)$", line.strip())
            if not match:
                continue
            address = match.group(1).lower()
            name = match.group(2).strip()
            devices[address] = name
            print_success(f"BT: {name} | {address}")
        return devices

    def _scan_bluetoothctl(self, timeout: int) -> Dict[str, str]:
        subprocess.run(
            ["bluetoothctl", "power", "on"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        subprocess.run(
            ["bluetoothctl", "--timeout", str(timeout), "scan", "on"],
            capture_output=True,
            text=True,
            timeout=timeout + 15,
            check=False,
        )
        proc = subprocess.run(
            ["bluetoothctl", "devices"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        subprocess.run(
            ["bluetoothctl", "scan", "off"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

        devices: Dict[str, str] = {}
        for line in proc.stdout.splitlines():
            match = re.match(r"^Device\s+([0-9A-Fa-f:]{17})\s+(.+)$", line.strip())
            if not match:
                continue
            address = match.group(1).lower()
            name = match.group(2).strip()
            devices[address] = name
            print_success(f"BT: {name} | {address}")
        return devices
