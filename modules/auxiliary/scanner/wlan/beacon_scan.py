#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Sniff 802.11 beacon frames on a monitor-mode interface."""

from __future__ import annotations

from typing import Dict

from kittysploit import *


class Module(Auxiliary):
    __info__ = {
        "name": "WiFi Beacon Scanner",
        "description": (
            "Capture 802.11 beacon frames on a monitor-mode interface and list "
            "visible wireless networks (SSID and BSSID)."
        ),
        "author": ["KittySploit Team"],
        "tags": ["scanner", "wlan", "wifi", "wireless", "discovery", "802.11"],
        "references": [
            "https://attack.mitre.org/techniques/T1016/",
        ],
        "attack": {
            "tactics": ["TA0007", "Discovery"],
            "techniques": ["T1016"],
            "prerequisites": [
                "Wireless adapter capable of monitor mode",
                "Interface in monitor mode (e.g. wlan0mon via airmon-ng)",
                "Root or CAP_NET_RAW on the capture interface",
            ],
            "detections": [
                "802.11 passive monitoring on adjacent channels",
            ],
            "artifacts": [
                "Wireless IDS / WIDS events",
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
        'chain':         {'produces_capabilities': [{'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'ssrf_primitive', 'from_detail': ''},
                                   {'capability': 'db_access', 'from_detail': ''},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 'file_read', 'from_detail': 'lfi_path'},
                                   {'capability': 'lfi_param', 'from_detail': 'lfi_param'},
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 's7comm', 'from_detail': ''},
                                   {'capability': 's7comm', 'from_detail': ''}],
         'consumes_capabilities': [],
         'option_bindings': {},
         'suggested_followups': []},
    },
    }

    iface = OptString("wlan0mon", "Monitor-mode wireless interface", required=True)
    timeout = OptInteger(30, "Capture duration in seconds", required=False)
    show_hidden = OptBool(True, "Include hidden networks (empty SSID)", required=False)

    def check(self):
        try:
            from scapy.all import Dot11, sniff  # noqa: F401
        except ImportError:
            print_error("scapy is not installed. Install it with: pip install scapy")
            return False

        iface = str(self.iface or "").strip()
        if not iface:
            print_error("Interface name is required")
            return False

        try:
            from scapy.all import get_if_list

            if iface not in get_if_list():
                print_warning(f"Interface {iface} not found in scapy interface list")
        except Exception:
            pass

        return True

    def run(self):
        from scapy.all import Dot11, sniff

        iface = str(self.iface or "wlan0mon").strip()
        timeout = max(1, int(self.timeout or 30))
        show_hidden = bool(self.show_hidden)
        networks: Dict[str, str] = {}

        print_info(f"WiFi beacon scan on {iface} for {timeout}s")
        print_info("=" * 72)
        print_status("Listening for beacon frames (Ctrl+C to stop early)...")

        def on_packet(packet):
            if not packet.haslayer(Dot11):
                return
            dot11 = packet[Dot11]
            if dot11.type != 0 or dot11.subtype != 8:
                return

            bssid = dot11.addr2
            if not bssid:
                return

            raw_ssid = packet.info.decode(errors="ignore") if hasattr(packet, "info") else ""
            ssid = raw_ssid.strip()
            if not ssid:
                if not show_hidden:
                    return
                ssid = "<hidden>"

            previous = networks.get(bssid)
            if previous is None or (previous == "<hidden>" and ssid != "<hidden>"):
                networks[bssid] = ssid
                print_success(f"SSID: {ssid} | BSSID: {bssid}")

        try:
            sniff(iface=iface, prn=on_packet, timeout=timeout, store=0)
        except PermissionError:
            print_error(
                f"Permission denied capturing on {iface}. "
                "Run as root or grant CAP_NET_RAW, and ensure monitor mode is enabled."
            )
            return False
        except OSError as exc:
            print_error(f"Could not sniff on {iface}: {exc}")
            print_info("Tip: put the interface in monitor mode, e.g. sudo airmon-ng start wlan0")
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
