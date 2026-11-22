#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Sniff 802.11 beacon frames on a monitor-mode interface."""

from __future__ import annotations
from typing import Dict
from kittysploit import *
from lib.protocols.wlan.wlan_client import Wlan_client


class Module(Auxiliary, Wlan_client):
    __info__ = {
        "name": "WiFi Beacon Scanner",
        "description": (
            "Capture 802.11 beacon frames on a monitor-mode interface and list "
            "visible wireless networks (SSID and BSSID)."
        ),
        "author": ["KittySploit Team"],
        "tags": ["scanner", "wlan", "wifi", "wireless", "discovery", "802.11"],
        "references": [
            "https://attack.mitre.org/techniques/T1016/"],
        "attack": {
            "tactics": ["TA0007", "Discovery"],
            "techniques": ["T1016"],
            "prerequisites": [
                "Wireless adapter capable of monitor mode",
                "Interface in monitor mode (KittySploit lib/protocols/wlan)",
                "Root or CAP_NET_RAW on the capture interface"],
            "detections": [
                "802.11 passive monitoring on adjacent channels"],
            "artifacts": [
                "Wireless IDS / WIDS events"],
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
        'chain':         {'produces_capabilities': [{'capability': 'admin_surface', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    timeout = OptInteger(30, "Capture duration in seconds", required=False)
    show_hidden = OptBool(True, "Include hidden networks (empty SSID)", required=False)

    def check(self):
        return self.wlan_check_iface()

    def run(self):
        iface = str(self.iface or "wlan0mon").strip()
        timeout = max(1, int(self.timeout or 30))
        show_hidden = bool(self.show_hidden)
        networks: Dict[str, str] = {}

        print_info(f"WiFi beacon scan on {iface} for {timeout}s")
        print_info("=" * 72)
        print_status("Listening for beacon frames (Ctrl+C to stop early)...")

        def on_frame(raw: bytes, _rssi: int | None) -> None:
            beacon = self.wlan_parse_beacon(raw)
            if not beacon:
                return
            bssid = beacon.bssid
            ssid = (beacon.ssid or "").strip()
            if not ssid:
                if not show_hidden:
                    return
                ssid = "<hidden>"
            previous = networks.get(bssid)
            if previous is None or (previous == "<hidden>" and ssid != "<hidden>"):
                networks[bssid] = ssid
                print_success(f"SSID: {ssid} | BSSID: {bssid}")

        try:
            self.wlan_sniff(on_frame, timeout=float(timeout))
        except PermissionError:
            print_error(
                f"Permission denied capturing on {iface}. "
                "Run as root or grant CAP_NET_RAW, and ensure monitor mode is enabled."
            )
            return False
        except OSError as exc:
            print_error(f"Could not sniff on {iface}: {exc}")
            print_info("Tip: enable monitor mode on the capture interface before running")
            return False
        except KeyboardInterrupt:
            print_warning("Capture interrupted by user")

        print_info("=" * 72)
        if networks:
            print_success(f"Scan complete: {len(networks)} network(s) observed")
            for bssid in sorted(networks):
                print_info(f"  {networks[bssid]:32} {bssid}")
            return True

        print_warning("No beacon frames captured — check interface, channel, and monitor mode")
        return False