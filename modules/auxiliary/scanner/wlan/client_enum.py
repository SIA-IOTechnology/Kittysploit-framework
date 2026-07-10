#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Enumerate 802.11 wireless clients from probe, association, and data frames."""

from __future__ import annotations

from typing import Dict, Set

from kittysploit import *


class Module(Auxiliary):
    __info__ = {
        "name": "WiFi Client Enumerator",
        "description": (
            "Passively enumerate wireless clients on a monitor-mode interface by "
            "observing probe requests, association frames, and data traffic."
        ),
        "author": ["KittySploit Team"],
        "tags": ["scanner", "wlan", "wifi", "wireless", "enumeration", "802.11", "clients"],
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
    bssid = OptString("", "Filter on AP BSSID (empty = all access points)", required=False)

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
        bssid_filter = str(self.bssid or "").strip().lower()

        # bssid -> {client_mac: {frame_types}}
        ap_clients: Dict[str, Dict[str, Set[str]]] = {}
        live_seen: Set[tuple] = set()

        print_info(f"WiFi client enumeration on {iface} for {timeout}s")
        if bssid_filter:
            print_info(f"BSSID filter: {bssid_filter}")
        print_info("=" * 72)
        print_status("Listening for client activity (Ctrl+C to stop early)...")

        def record(bssid: str, client: str, frame_type: str) -> None:
            if not bssid or not client:
                return
            if bssid.lower() in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
                return
            if client.lower() in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
                return
            if bssid_filter and bssid.lower() != bssid_filter:
                return

            live_key = (bssid, client, frame_type)
            if live_key in live_seen:
                return
            live_seen.add(live_key)

            ap_clients.setdefault(bssid, {}).setdefault(client, set()).add(frame_type)
            print_success(f"BSSID: {bssid} | Client: {client} | via {frame_type}")

        def on_packet(packet):
            if not packet.haslayer(Dot11):
                return
            dot11 = packet[Dot11]

            if dot11.type == 0:
                subtype = int(dot11.subtype)
                if subtype == 4:
                    # Probe request: addr2=client, addr1=target AP or broadcast
                    target = dot11.addr1
                    if target and target.lower() != "ff:ff:ff:ff:ff:ff":
                        record(target, dot11.addr2, "probe")
                elif subtype in (0, 2, 3):
                    # Association / reassociation request: addr1=AP, addr2=client
                    record(dot11.addr1, dot11.addr2, "association")
                elif subtype == 11:
                    # Authentication: addr1=AP, addr2=client
                    record(dot11.addr1, dot11.addr2, "authentication")

            elif dot11.type == 2:
                to_ds = bool(dot11.FCfield & 0x1)
                from_ds = bool(dot11.FCfield & 0x2)
                if to_ds and not from_ds:
                    # Client -> AP
                    record(dot11.addr1, dot11.addr2, "data")
                elif from_ds and not to_ds:
                    # AP -> Client
                    record(dot11.addr2, dot11.addr1, "data")

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
        if ap_clients:
            client_total = len({c for clients in ap_clients.values() for c in clients})
            print_success(
                f"Enumeration complete: {len(ap_clients)} AP(s), {client_total} unique client(s)"
            )
            for ap in sorted(ap_clients):
                clients = ap_clients[ap]
                print_info(f"  {ap} ({len(clients)} client(s))")
                for client in sorted(clients):
                    types = ", ".join(sorted(clients[client]))
                    print_info(f"    {client}  [{types}]")
            return True

        print_warning("No clients observed — check interface, channel, and monitor mode")
        return False
