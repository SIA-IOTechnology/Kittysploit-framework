#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Passive 802.1X / WPA-Enterprise beacon survey."""

from __future__ import annotations
from kittysploit import *
from lib.protocols.wlan.enterprise import assess_enterprise
from lib.protocols.wlan.wlan_client import Wlan_client


class Module(Auxiliary, Wlan_client):
    __info__ = {
        "name": "WiFi Enterprise (802.1X) Scanner",
        "description": "List APs using 802.1X / FT-802.1X AKMs and mixed PSK deployments.",
        "author": ["KittySploit Team"],
        "tags": ["scanner", "wlan", "wifi", "802.1x", "enterprise"],
        "references": ["https://attack.mitre.org/techniques/T1040/"],
    }

    timeout = OptInteger(60, "Scan duration", required=False)
    enterprise_only = OptBool(True, "Hide pure PSK APs", required=False)

    def check(self):
        return self.wlan_check_iface()

    def run(self):
        duration = max(10, int(self.timeout or 60))
        seen: set[str] = set()
        print_info(f"802.1X survey ({duration}s)")

        def on_frame(raw: bytes, rssi: int | None) -> None:
            beacon = self.wlan_parse_beacon(raw, rssi=rssi)
            if not beacon or beacon.bssid in seen:
                return
            prof = assess_enterprise(beacon.security, beacon.bssid)
            if enterprise_only and not prof.eap_8021x:
                return
            seen.add(beacon.bssid)
            print_success(
                f"{beacon.bssid} | {beacon.ssid or '<hidden>'} | "
                f"eap={'Y' if prof.eap_8021x else 'N'} psk_mix={'Y' if prof.psk_also else 'N'}"
            )
            print_status(f"  {prof.note}")

        try:
            self.wlan_sniff(on_frame, timeout=float(duration))
        except (PermissionError, OSError) as exc:
            print_error(str(exc))
            return False
        print_info(f"BSSIDs: {len(seen)}")
        return True