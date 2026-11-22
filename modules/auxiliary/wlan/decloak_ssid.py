#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Reveal hidden SSIDs from probe responses and associated data frames."""

from __future__ import annotations
from kittysploit import *
from lib.protocols.wlan.wlan_client import Wlan_client


class Module(Auxiliary, Wlan_client):
    __info__ = {
        "name": "WiFi Hidden SSID Decloak",
        "description": (
            "Passive decloaking: correlate hidden beacons with probe responses and "
            "association traffic to recover broadcast SSIDs."
        ),
        "author": ["KittySploit Team"],
        "tags": ["wlan", "wifi", "decloak", "hidden", "802.11"],
        "references": ["https://attack.mitre.org/techniques/T1016/"],
    }

    timeout = OptInteger(60, "Capture duration in seconds", required=False)
    bssid = OptString("", "Optional BSSID filter", required=False)

    def check(self):
        return self.wlan_check_iface()

    def run(self):
        timeout = max(5, int(self.timeout or 60))
        target_bssid = str(self.bssid or "").strip().lower()
        hidden: dict[str, str] = {}

        print_info(f"Decloak pass on {self.iface} ({timeout}s)")
        print_info("=" * 72)

        def on_frame(raw: bytes, _rssi: int | None) -> None:
            frame = self.wlan_strip_radiotap(raw)
            if len(frame) < 24:
                return
            fc0 = frame[0]
            subtype = (fc0 & 0xF0) >> 4
            beacon = self.wlan_parse_beacon(raw)
            if beacon:
                if target_bssid and beacon.bssid.lower() != target_bssid:
                    return
                if not beacon.ssid:
                    hidden.setdefault(beacon.bssid, "")
            if subtype in (5, 0, 1):
                body_start = 24 + (8 if subtype == 5 else 0)
                if body_start >= len(frame):
                    return
                ssid = self.wlan_parse_ssid(frame[body_start:])
                if not ssid:
                    return
                bssid = beacon.bssid if beacon else self.wlan_mac_to_str(frame[16:22])
                if target_bssid and bssid.lower() != target_bssid:
                    return
                if bssid and (bssid in hidden or not hidden.get(bssid)):
                    hidden[bssid] = ssid
                    print_success(f"Decloaked {bssid} → SSID: {ssid}")

        try:
            self.wlan_sniff(on_frame, timeout=float(timeout))
        except (PermissionError, OSError) as exc:
            print_error(f"Capture failed: {exc}")
            return False

        print_info("=" * 72)
        revealed = {k: v for k, v in hidden.items() if v}
        if revealed:
            print_success(f"Recovered {len(revealed)} hidden network name(s)")
            for mac, ssid in sorted(revealed.items()):
                print_info(f"  {mac} = {ssid}")
            return True
        print_warning("No hidden SSIDs recovered — try longer TIMEOUT or active decloak")
        return False