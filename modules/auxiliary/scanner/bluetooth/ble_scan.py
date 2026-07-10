#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Discover nearby Bluetooth Low Energy (BLE) devices."""

from __future__ import annotations

import asyncio
from typing import Dict

from kittysploit import *


class Module(Auxiliary):
    __info__ = {
        "name": "Bluetooth LE Scanner",
        "description": "Discover nearby BLE devices using passive/active advertisement scanning.",
        "author": ["KittySploit Team"],
        "tags": ["scanner", "bluetooth", "ble", "wireless", "discovery"],
        "references": [
            "https://attack.mitre.org/techniques/T1016/",
        ],
        "attack": {
            "tactics": ["TA0007", "Discovery"],
            "techniques": ["T1016"],
            "prerequisites": [
                "Host Bluetooth adapter with BLE support",
                "BlueZ on Linux or equivalent BLE stack",
            ],
            "detections": [
                "BLE advertisement monitoring on operator host",
            ],
            "artifacts": [
                "Local Bluetooth scan logs",
            ],
        },
    'agent': {
        'risk': '',
        'effects': ['wireless_sniff'],
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

    timeout = OptInteger(10, "Scan duration in seconds", required=False)
    adapter = OptString("", "Bluetooth adapter (empty = default)", required=False)

    def check(self):
        try:
            import bleak  # noqa: F401
        except ImportError:
            print_error("bleak is not installed. Install it with: pip install bleak")
            return False
        return True

    def run(self):
        timeout = max(1, int(self.timeout or 10))
        adapter = str(self.adapter or "").strip()

        print_info(f"BLE scan for {timeout}s")
        print_info("=" * 72)

        try:
            devices = asyncio.run(self._scan(timeout, adapter))
        except Exception as exc:
            print_error(f"BLE scan failed: {exc}")
            print_info("Ensure Bluetooth is enabled and the adapter is not blocked (rfkill)")
            return False

        print_info("=" * 72)
        if not devices:
            print_warning("No BLE devices discovered")
            return False

        print_success(f"Discovered {len(devices)} BLE device(s)")
        for address in sorted(devices):
            entry = devices[address]
            name = entry.get("name") or "<unknown>"
            rssi = entry.get("rssi")
            suffix = f" | RSSI: {rssi} dBm" if rssi is not None else ""
            print_info(f"  {name:32} {address}{suffix}")
        return True

    async def _scan(self, timeout: int, adapter: str) -> Dict[str, Dict]:
        from bleak import BleakScanner

        kwargs = {"timeout": float(timeout)}
        if adapter:
            kwargs["adapter"] = adapter

        found: Dict[str, Dict] = {}

        def callback(device, advertisement_data):
            address = device.address
            current = found.get(address, {})
            name = device.name or advertisement_data.local_name
            rssi = getattr(advertisement_data, "rssi", None)
            if name:
                current["name"] = name
            if rssi is not None:
                current["rssi"] = rssi
            found[address] = current
            label = current.get("name") or "<unknown>"
            rssi_text = f" | RSSI: {rssi} dBm" if rssi is not None else ""
            print_success(f"BLE: {label} | {address}{rssi_text}")

        scanner = BleakScanner(detection_callback=callback, **kwargs)
        await scanner.start()
        await asyncio.sleep(timeout)
        await scanner.stop()

        if not found:
            # Fallback for bleak versions without callback-only discovery
            legacy = await BleakScanner.discover(timeout=timeout, adapter=adapter or None)
            for device in legacy:
                found[device.address] = {
                    "name": device.name or "",
                    "rssi": getattr(device, "rssi", None),
                }
                label = device.name or "<unknown>"
                print_success(f"BLE: {label} | {device.address}")

        return found
