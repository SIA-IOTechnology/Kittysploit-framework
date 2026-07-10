#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Detect 802.11 deauthentication and disassociation frames (passive WIDS)."""

from __future__ import annotations

from typing import Dict, Set

from kittysploit import *


_DEAUTH_REASONS = {
    1: "Unspecified",
    2: "Previous authentication no longer valid",
    3: "Station leaving (or deauthenticated)",
    4: "Inactivity",
    5: "AP unable to handle all stations",
    6: "Class 2 frame from nonauthenticated station",
    7: "Class 3 frame from nonassociated station",
    8: "Station leaving (disassociated)",
    15: "4-Way handshake timeout",
    16: "Group key handshake timeout",
    23: "802.1X authentication failed",
}


class Module(Auxiliary):
    __info__ = {
        "name": "WiFi Deauth Detector",
        "description": (
            "Passively detect 802.11 deauthentication and disassociation frames on a "
            "monitor-mode interface to spot deauth floods or rogue disconnect attacks."
        ),
        "author": ["KittySploit Team"],
        "tags": ["scanner", "wlan", "wifi", "wireless", "deauth", "wids", "802.11"],
        "references": [
            "https://attack.mitre.org/techniques/T1498/",
        ],
        "attack": {
            "tactics": ["TA0040", "Impact"],
            "techniques": ["T1498"],
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
        'produces': ['risk_signals', 'tech_hints'],
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
    timeout = OptInteger(60, "Capture duration in seconds", required=False)
    bssid = OptString("", "Filter on AP BSSID (empty = all access points)", required=False)
    alert_threshold = OptInteger(
        5,
        "Warn when this many deauth/disassoc frames hit the same victim MAC",
        required=False,
    )

    def check(self):
        try:
            from scapy.all import Dot11, Dot11Deauth, Dot11Disas, sniff  # noqa: F401
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
        from scapy.all import Dot11, Dot11Deauth, Dot11Disas, sniff

        iface = str(self.iface or "wlan0mon").strip()
        timeout = max(1, int(self.timeout or 60))
        bssid_filter = str(self.bssid or "").strip().lower()
        alert_threshold = max(1, int(self.alert_threshold or 5))

        events: Dict[str, int] = {}
        types_seen: Dict[str, Set[str]] = {}
        total_events = 0

        print_info(f"WiFi deauth/disassoc detection on {iface} for {timeout}s")
        if bssid_filter:
            print_info(f"BSSID filter: {bssid_filter}")
        print_info(f"Flood alert threshold: {alert_threshold} frame(s) per victim MAC")
        print_info("=" * 72)
        print_status("Listening for deauth/disassoc frames (Ctrl+C to stop early)...")

        def reason_text(frame_type: str, packet) -> str:
            layer = packet.getlayer(Dot11Deauth) if frame_type == "deauth" else packet.getlayer(Dot11Disas)
            if layer is None:
                return "unknown"
            code = int(getattr(layer, "reason", 0))
            label = _DEAUTH_REASONS.get(code, "reserved/unknown")
            return f"{code} ({label})"

        def on_packet(packet):
            nonlocal total_events
            if not packet.haslayer(Dot11):
                return

            dot11 = packet[Dot11]
            if dot11.type != 0:
                return

            subtype = int(dot11.subtype)
            if subtype == 12:
                frame_type = "deauth"
            elif subtype == 10:
                frame_type = "disassoc"
            else:
                return

            bssid = dot11.addr3 or ""
            src = dot11.addr2 or ""
            dst = dot11.addr1 or ""
            if bssid_filter and bssid.lower() != bssid_filter:
                return

            victim = dst
            total_events += 1
            events[victim] = events.get(victim, 0) + 1
            types_seen.setdefault(victim, set()).add(frame_type)
            reason = reason_text(frame_type, packet)

            print_warning(
                f"{frame_type.upper()} | BSSID: {bssid} | From: {src} | To: {dst} | Reason: {reason}"
            )
            if events[victim] == alert_threshold:
                print_error(
                    f"Possible deauth flood against {victim} "
                    f"({events[victim]} frame(s) observed)"
                )
            elif events[victim] > alert_threshold and events[victim] % alert_threshold == 0:
                print_error(
                    f"Deauth flood continues against {victim} ({events[victim]} frame(s) total)"
                )

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
        if total_events:
            victims = len(events)
            print_success(f"Detection complete: {total_events} event(s) affecting {victims} MAC(s)")
            for victim in sorted(events, key=lambda v: events[v], reverse=True):
                count = events[victim]
                kinds = ", ".join(sorted(types_seen.get(victim, set())))
                level = "ALERT" if count >= alert_threshold else "info"
                line = f"  {victim}: {count} event(s) [{kinds}]"
                if level == "ALERT":
                    print_error(line)
                else:
                    print_info(line)
            return True

        print_info("No deauthentication or disassociation frames observed during capture")
        return False
