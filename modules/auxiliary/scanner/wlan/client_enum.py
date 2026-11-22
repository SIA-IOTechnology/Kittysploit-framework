#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Enumerate 802.11 wireless clients from probe, association, and data frames."""

from __future__ import annotations
from typing import Dict, Set
from kittysploit import *
from lib.protocols.wlan.wlan_client import Wlan_client


class Module(Auxiliary, Wlan_client):
    __info__ = {
        "name": "WiFi Client Enumerator",
        "description": (
            "Passively enumerate wireless clients on a monitor-mode interface by "
            "observing probe requests, association frames, and data traffic."
        ),
        "author": ["KittySploit Team"],
        "tags": ["scanner", "wlan", "wifi", "wireless", "enumeration", "802.11", "clients"],
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
    bssid = OptString("", "Filter on AP BSSID (empty = all access points)", required=False)

    def check(self):
        return self.wlan_check_iface()

    def run(self):
        timeout = max(1, int(self.timeout or 30))
        bssid_filter = str(self.bssid or "").strip().lower()
        ap_clients: Dict[str, Dict[str, Set[str]]] = {}
        live_seen: Set[tuple] = set()

        print_info(f"WiFi client enumeration on {self.iface} for {timeout}s")
        if bssid_filter:
            print_info(f"BSSID filter: {bssid_filter}")
        print_info("=" * 72)

        def record(act) -> None:
            if bssid_filter and act.bssid.lower() != bssid_filter:
                return
            live_key = (act.bssid, act.client, act.frame_type)
            if live_key in live_seen:
                return
            live_seen.add(live_key)
            ap_clients.setdefault(act.bssid, {}).setdefault(act.client, set()).add(act.frame_type)
            self.wlan_register_client(act.bssid, act.client, frame_type=act.frame_type)
            print_success(f"BSSID: {act.bssid} | Client: {act.client} | via {act.frame_type}")

        def on_frame(raw: bytes, _rssi: int | None) -> None:
            act = self.wlan_parse_client_activity(raw)
            if act:
                record(act)

        try:
            self.wlan_sniff(on_frame, timeout=float(timeout))
        except (PermissionError, OSError) as exc:
            print_error(f"Capture failed: {exc}")
            return False

        print_info("=" * 72)
        if not ap_clients:
            print_warning("No clients observed")
            return False
        client_total = len({c for clients in ap_clients.values() for c in clients})
        print_success(f"Enumeration complete: {len(ap_clients)} AP(s), {client_total} client(s)")
        for ap in sorted(ap_clients):
            for client, types in sorted(ap_clients[ap].items()):
                print_info(f"  {ap} | {client} [{', '.join(sorted(types))}]")
        return True