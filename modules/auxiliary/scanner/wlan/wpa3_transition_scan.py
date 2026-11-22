#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Detect WPA3 transition / WPA2 downgrade exposure from beacon RSN."""

from __future__ import annotations
from kittysploit import *
from lib.protocols.wlan.wlan_client import Wlan_client
from lib.protocols.wlan.wpa3 import assess_wpa3_downgrade


class Module(Auxiliary, Wlan_client):
    __info__ = {
        "name": "WiFi WPA3 Transition Scanner",
        "description": (
            "Passive beacon survey flagging WPA3-SAE APs that still advertise WPA2-PSK "
            "(transition mode) and PMF posture for downgrade risk."
        ),
        "author": ["KittySploit Team"],
        "tags": ["scanner", "wlan", "wifi", "wpa3", "802.11"],
        "references": ["https://attack.mitre.org/techniques/T1565/002/"],
    }

    timeout = OptInteger(60, "Scan duration", required=False)
    bssid = OptString("", "Filter BSSID", required=False)
    risky_only = OptBool(False, "Only print high/medium transition risk", required=False)

    def check(self):
        return self.wlan_check_iface()

    def run(self):
        duration = max(10, int(self.timeout or 60))
        filt = str(self.bssid or "").strip().lower()
        seen: set[str] = set()

        print_info(f"WPA3 transition scan ({duration}s)")
        print_info("=" * 72)

        def on_frame(raw: bytes, rssi: int | None) -> None:
            beacon = self.wlan_parse_beacon(raw, rssi=rssi)
            if not beacon:
                return
            if filt and beacon.bssid.lower() != filt:
                return
            if beacon.bssid in seen:
                return
            seen.add(beacon.bssid)
            report = assess_wpa3_downgrade(beacon.security)
            if risky_only and report["risk"] not in ("high", "medium"):
                return
            marker = {"high": "[!]", "medium": "[~]", "low": "[ ]", "none": "[ ]"}.get(
                report["risk"], "[ ]"
            )
            print_success(
                f"{marker} {beacon.bssid} | {beacon.ssid or '<hidden>'} | "
                f"risk={report['risk']} | pmf={'req' if report['pmf_required'] else 'opt'} | "
                f"trans={'Y' if report['transition'] else 'N'}"
            )
            if report["risk"] in ("high", "medium"):
                print_warning(f"  {report['note']}")

        try:
            self.wlan_sniff(on_frame, timeout=float(duration))
        except (PermissionError, OSError) as exc:
            print_error(f"Scan failed: {exc}")
            return False

        if not seen:
            print_warning("No beacons captured")
            return False
        print_info(f"Surveyed {len(seen)} BSSIDs")
        return True