#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Sniff 802.11 probe requests to discover SSIDs and probing clients."""

from __future__ import annotations
from typing import Dict, Set, Tuple
from kittysploit import *
from lib.protocols.wlan.wlan_client import Wlan_client


class Module(Auxiliary, Wlan_client):
    __info__ = {
        "name": "WiFi Probe Request Scanner",
        "description": (
            "Capture 802.11 probe requests on a monitor-mode interface to reveal "
            "SSID names (including hidden networks) and client MAC addresses."
        ),
        "author": ["KittySploit Team"],
        "tags": ["scanner", "wlan", "wifi", "wireless", "discovery", "802.11", "probe"],
        "references": ["https://attack.mitre.org/techniques/T1016/"],
        "attack": {
            "tactics": ["TA0007", "Discovery"],
            "techniques": ["T1016"],
            "prerequisites": [
                "Wireless adapter capable of monitor mode",
                "Interface in monitor mode via lib/protocols/wlan",
                "Root or CAP_NET_RAW on the capture interface",
            ],
        },
    }

    timeout = OptInteger(30, "Capture duration in seconds", required=False)
    filter_ssid = OptString("", "Only show probes matching this SSID (empty = all)", required=False)
    show_wildcard = OptBool(True, "Include wildcard probes (empty SSID / broadcast scan)", required=False)

    def check(self):
        return self.wlan_check_iface()

    def run(self):
        timeout = max(1, int(self.timeout or 30))
        filter_ssid = str(self.filter_ssid or "").strip()
        show_wildcard = bool(self.show_wildcard)
        ssid_clients: Dict[str, Set[str]] = {}
        seen: Set[Tuple[str, str, str]] = set()

        print_info(f"WiFi probe request scan on {self.iface} for {timeout}s")
        if filter_ssid:
            print_info(f"SSID filter: {filter_ssid}")
        print_info("=" * 72)

        def on_frame(raw: bytes, _rssi: int | None) -> None:
            probe = self.wlan_parse_probe_request(raw)
            if not probe:
                return
            ssid = "<wildcard>" if probe.wildcard else probe.ssid
            if not show_wildcard and probe.wildcard:
                return
            if filter_ssid and ssid not in (filter_ssid, "<wildcard>"):
                return
            key = (ssid, probe.client, probe.target_bssid)
            if key in seen:
                return
            seen.add(key)
            ssid_clients.setdefault(ssid, set()).add(probe.client)
            target = probe.target_bssid or "broadcast"
            print_success(f"SSID: {ssid} | Client: {probe.client} | Target: {target}")
            if probe.target_bssid and not probe.wildcard:
                self.wlan_register_client(probe.target_bssid, probe.client, frame_type="probe", ssid_probe=ssid)

        try:
            self.wlan_sniff(on_frame, timeout=float(timeout))
        except (PermissionError, OSError) as exc:
            print_error(f"Capture failed: {exc}")
            return False

        print_info("=" * 72)
        if not ssid_clients:
            print_warning("No probe requests captured")
            return False
        client_total = len({c for clients in ssid_clients.values() for c in clients})
        print_success(f"Scan complete: {len(ssid_clients)} SSID(s), {client_total} unique client(s)")
        for ssid in sorted(ssid_clients, key=lambda s: (s == "<wildcard>", s)):
            for client in sorted(ssid_clients[ssid]):
                print_info(f"  {ssid} → {client}")
        return True