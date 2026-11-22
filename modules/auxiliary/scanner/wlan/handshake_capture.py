#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Passively capture WPA/WPA2 EAPOL handshakes on a monitor-mode interface."""

from __future__ import annotations
import os
import time
from typing import Dict, List, Tuple
from kittysploit import *
from lib.protocols.wlan.wlan_client import Wlan_client


class Module(Auxiliary, Wlan_client):
    __info__ = {
        "name": "WiFi Handshake Capture",
        "description": (
            "Passively capture WPA/WPA2 EAPOL key exchanges on a monitor-mode interface "
            "and save matching frames to a PCAP file for offline cracking."
        ),
        "author": ["KittySploit Team"],
        "tags": ["scanner", "wlan", "wifi", "wireless", "eapol", "handshake", "802.11"],
        "references": ["https://attack.mitre.org/techniques/T1040/"],
        "attack": {
            "tactics": ["TA0006", "Credential Access"],
            "techniques": ["T1040"],
            "prerequisites": [
                "Wireless adapter capable of monitor mode",
                "Interface in monitor mode via lib/protocols/wlan",
                "Root or CAP_NET_RAW on the capture interface",
                "A client associating or reassociating to the target AP during capture",
            ],
            "detections": ["802.11 passive monitoring on adjacent channels"],
            "artifacts": ["Wireless IDS / WIDS events", "Saved PCAP files on operator host"],
        },
        "agent": {
            "risk": "",
            "effects": ["wireless_sniff"],
            "expected_requests": 1,
            "reversible": True,
            "approval_required": False,
            "produces": ["evidence", "tech_hints"],
            "cost": 1.0,
            "noise": 0.5,
            "value": 1.0,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": [],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": [],
                "param_any": [],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [{"capability": "admin_surface", "from_detail": ""}],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": ["auxiliary/wlan/pcap_analyze", "auxiliary/wlan/wpa_cpu_crack"],
            },
        },
    }

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
        return self.wlan_check_iface()

    def run(self):
        iface = str(self.iface or "wlan0mon").strip()
        timeout = max(1, int(self.timeout or 120))
        bssid_filter = str(self.bssid or "").strip().lower()
        client_filter = str(self.client or "").strip().lower()
        min_keys = max(1, min(int(self.min_eapol_keys or 2), 4))
        stop_on_capture = bool(self.stop_on_capture)

        captures: Dict[Tuple[str, str], List[bytes]] = {}
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

        def matches_filters(ap: str, station: str) -> bool:
            if bssid_filter and ap.lower() != bssid_filter:
                return False
            if client_filter and station.lower() != client_filter:
                return False
            return bool(ap and station)

        def save_handshake(ap: str, station: str, packets: List[bytes]) -> None:
            path = str(self.output or "").strip()
            if not path:
                stamp = time.strftime("%Y%m%d_%H%M%S")
                ap_tag = ap.replace(":", "")
                path = f"wlan_handshake_{ap_tag}_{stamp}.pcap"
            path = os.path.abspath(path)
            self.wlan_write_pcap(path, packets)
            saved_paths.append(path)
            print_success(f"Handshake saved: {path} ({len(packets)} frame(s), AP {ap}, client {station})")
            print_info(
                "Convert with: use auxiliary/wlan/pcap_analyze then auxiliary/wlan/wpa_cpu_crack"
            )

        def on_frame(raw: bytes, _rssi: int | None) -> None:
            if stop_capture["flag"]:
                return
            eap = self.wlan_parse_eapol(raw)
            if not eap:
                return
            ap, station = eap.bssid, eap.station
            if not matches_filters(ap, station):
                return
            pair = (ap, station)
            captures.setdefault(pair, []).append(raw)
            key_counts[pair] = key_counts.get(pair, 0) + 1
            count = key_counts[pair]
            print_status(f"EAPOL-Key {count}/{min_keys} | AP: {ap} | Client: {station}")
            if count >= min_keys:
                save_handshake(ap, station, captures[pair])
                if stop_on_capture:
                    stop_capture["flag"] = True

        try:
            self.wlan_sniff(
                on_frame,
                timeout=float(timeout),
                stop_when=lambda: stop_capture["flag"],
            )
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