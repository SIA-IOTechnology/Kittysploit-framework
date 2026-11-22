#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Detect 802.11 deauthentication and disassociation frames (passive WIDS)."""

from __future__ import annotations
from typing import Dict, Set
from kittysploit import *
from lib.protocols.wlan.wlan_client import Wlan_client


class Module(Auxiliary, Wlan_client):
    __info__ = {
        "name": "WiFi Deauth Detector",
        "description": (
            "Passively detect 802.11 deauthentication and disassociation frames on a "
            "monitor-mode interface to spot deauth floods or rogue disconnect attacks."
        ),
        "author": ["KittySploit Team"],
        "tags": ["scanner", "wlan", "wifi", "wireless", "deauth", "wids", "802.11"],
        "references": ["https://attack.mitre.org/techniques/T1498/"],
        "attack": {
            "tactics": ["TA0040", "Impact"],
            "techniques": ["T1498"],
            "prerequisites": [
                "Wireless adapter capable of monitor mode",
                "Interface in monitor mode via lib/protocols/wlan",
                "Root or CAP_NET_RAW on the capture interface",
            ],
        },
    }

    timeout = OptInteger(60, "Capture duration in seconds", required=False)
    bssid = OptString("", "Filter on AP BSSID (empty = all access points)", required=False)
    alert_threshold = OptInteger(
        5,
        "Warn when this many deauth/disassoc frames hit the same victim MAC",
        required=False,
    )

    def check(self):
        return self.wlan_check_iface()

    def run(self):
        timeout = max(1, int(self.timeout or 60))
        bssid_filter = str(self.bssid or "").strip().lower()
        alert_threshold = max(1, int(self.alert_threshold or 5))
        events: Dict[str, int] = {}
        types_seen: Dict[str, Set[str]] = {}
        total_events = 0

        print_info(f"WiFi deauth/disassoc detection on {self.iface} for {timeout}s")
        if bssid_filter:
            print_info(f"BSSID filter: {bssid_filter}")
        print_info(f"Flood alert threshold: {alert_threshold} per victim MAC")
        print_info("=" * 72)

        def on_frame(raw: bytes, _rssi: int | None) -> None:
            nonlocal total_events
            evt = self.wlan_parse_deauth(raw)
            if not evt:
                return
            if bssid_filter and evt.bssid.lower() != bssid_filter:
                return
            frame_type = "disassoc" if evt.disassoc else "deauth"
            victim = evt.dest
            total_events += 1
            events[victim] = events.get(victim, 0) + 1
            types_seen.setdefault(victim, set()).add(frame_type)
            reason = self.wlan_deauth_reason(evt.reason)
            print_warning(
                f"{frame_type.upper()} | BSSID: {evt.bssid} | From: {evt.source} | "
                f"To: {evt.dest} | Reason: {reason}"
            )
            if events[victim] >= alert_threshold and events[victim] % alert_threshold == 0:
                print_error(f"Possible deauth flood against {victim} ({events[victim]} frame(s))")

        try:
            self.wlan_sniff(on_frame, timeout=float(timeout))
        except (PermissionError, OSError) as exc:
            print_error(f"Capture failed: {exc}")
            return False

        print_info("=" * 72)
        if not total_events:
            print_info("No deauthentication or disassociation frames observed")
            return False
        print_success(f"Detection complete: {total_events} event(s), {len(events)} victim MAC(s)")
        for victim in sorted(events, key=events.get, reverse=True):
            count = events[victim]
            kinds = ", ".join(sorted(types_seen.get(victim, set())))
            line = f"  {victim}: {count} event(s) [{kinds}]"
            print_error(line) if count >= alert_threshold else print_info(line)
        return True