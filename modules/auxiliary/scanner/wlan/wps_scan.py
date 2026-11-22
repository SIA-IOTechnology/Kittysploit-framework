#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Passive WPS enumeration from beacons and probe responses."""

from __future__ import annotations
from kittysploit import *
from lib.protocols.wlan.wlan_client import Wlan_client


class Module(Auxiliary, Wlan_client):
    __info__ = {
        "name": "WiFi WPS Scanner (Passive)",
        "description": (
            "Parse WPS vendor IEs from beacons to list manufacturer, model, WPS state, "
            "and whether the registrar is selected (no PIN brute-force)."
        ),
        "author": ["KittySploit Team"],
        "tags": ["scanner", "wlan", "wifi", "wps", "802.11"],
        "references": ["https://attack.mitre.org/techniques/T1016/"],
    }

    timeout = OptInteger(45, "Capture duration in seconds", required=False)
    bssid = OptString("", "Filter on AP BSSID", required=False)
    wps_only = OptBool(True, "Only show access points advertising WPS", required=False)

    def check(self):
        return self.wlan_check_iface()

    def run(self):
        timeout = max(5, int(self.timeout or 45))
        bssid_filter = str(self.bssid or "").strip().lower()
        found: dict[str, object] = {}

        print_info(f"WPS passive scan on {self.iface} ({timeout}s)")
        print_info("=" * 72)

        def on_frame(raw: bytes, rssi: int | None) -> None:
            beacon = self.wlan_parse_beacon(raw, rssi=rssi)
            if not beacon:
                return
            if bssid_filter and beacon.bssid.lower() != bssid_filter:
                return
            wps = self.wlan_wps_from_beacon(beacon)
            if wps_only and not wps:
                return
            self.wlan_register_beacon(beacon)
            if wps and beacon.bssid not in found:
                found[beacon.bssid] = wps
                print_success(
                    f"WPS | {beacon.bssid} | {beacon.ssid or '<hidden>'} | "
                    f"{wps.manufacturer or '?'} {wps.model_name or ''} | "
                    f"state={wps.wps_state or '?'} SR={'Y' if wps.selected_registrar else 'N'}"
                )
            elif not wps_only and beacon.bssid not in found:
                print_status(f"AP (no WPS IE) {beacon.bssid} {beacon.ssid or '<hidden>'}")

        try:
            self.wlan_sniff(on_frame, timeout=float(timeout))
        except (PermissionError, OSError) as exc:
            print_error(f"Capture failed: {exc}")
            return False

        print_info("=" * 72)
        if wps_only and not found:
            print_warning("No WPS-enabled access points seen")
            return False
        print_success(f"WPS scan complete: {len(found)} AP(s) with WPS")
        return True