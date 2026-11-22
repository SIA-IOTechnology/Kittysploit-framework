#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Active WPA2-PSK association probe against WPA3 transition APs (lab only)."""

from __future__ import annotations
import time
from kittysploit import *
from lib.protocols.wlan.wlan_client import Wlan_client
from lib.protocols.wlan.wpa3 import assess_wpa3_downgrade


class Module(Auxiliary, Wlan_client):
    __info__ = {
        "name": "WiFi WPA3 PSK Downgrade Probe",
        "description": (
            "On WPA3 transition targets, attempt WPA2-PSK association frames to see "
            "whether the AP still accepts the legacy AKM (downgrade exposure)."
        ),
        "author": ["KittySploit Team"],
        "tags": ["wlan", "wifi", "wpa3", "downgrade"],
        "references": ["https://attack.mitre.org/techniques/T1565/002/"],
        "attack": {
            "tactics": ["TA0006"],
            "techniques": ["T1565.002"],
            "prerequisites": ["Authorized target AP"],
        },
    }

    bssid = OptString("", "Target BSSID", required=True)
    ssid = OptString("", "SSID", required=True)
    channel = OptInteger(0, "Channel", required=False)
    sta_mac = OptString("", "Client MAC", required=False)
    dwell = OptInteger(8, "Listen after assoc inject", required=False)

    def check(self):
        if not str(self.bssid or "").strip() or not str(self.ssid or "").strip():
            print_error("BSSID and SSID required")
            return False
        return self.wlan_check_iface()

    def run(self):
        bssid = str(self.bssid).strip().lower()
        ssid = str(self.ssid).strip()
        sta = str(self.sta_mac or "").strip() or self.wlan_pmkid_sta_mac()
        dwell = max(3, int(self.dwell or 8))
        trans_info = None

        if int(self.channel or 0):
            self.wlan_set_channel(int(self.channel))

        def learn(raw: bytes, _rssi: int | None) -> None:
            nonlocal trans_info
            beacon = self.wlan_parse_beacon(raw)
            if beacon and beacon.bssid.lower() == bssid:
                trans_info = assess_wpa3_downgrade(beacon.security)

        try:
            self.wlan_sniff(learn, timeout=4.0)
        except (PermissionError, OSError):
            pass

        if trans_info:
            print_info(
                f"Beacon risk={trans_info['risk']} transition={trans_info['transition']} "
                f"pmf={'req' if trans_info['pmf_required'] else 'opt'}"
            )
        else:
            print_warning("Could not read target beacon — continuing blind probe")

        auth = self.wlan_build_open_auth(bssid, sta)
        assoc = self.wlan_build_assoc(bssid, sta, ssid)
        assoc_seen = {"ok": False, "status": -1}

        def on_mgmt(raw: bytes, _rssi: int | None) -> None:
            frame = self.wlan_strip_radiotap(raw)
            if len(frame) < 28:
                return
            subtype = (frame[0] & 0xF0) >> 4
            if subtype != 1:
                return
            if self.wlan_dot11_bssid(frame) != bssid:
                return
            assoc_seen["status"] = int.from_bytes(frame[26:28], "little")
            assoc_seen["ok"] = assoc_seen["status"] == 0

        print_status(f"Injecting WPA2-PSK assoc as {sta}")
        try:
            self.wlan_inject_raw([auth, assoc], count=2)
        except (PermissionError, OSError) as exc:
            print_error(f"Inject failed: {exc}")
            return False
        time.sleep(0.2)
        try:
            self.wlan_sniff(on_mgmt, timeout=float(dwell))
        except (PermissionError, OSError) as exc:
            print_warning(f"Listen failed: {exc}")

        if assoc_seen["ok"]:
            print_success("Association response status=0 — WPA2-PSK path still accepted")
            print_warning("Downgrade / transition exposure confirmed on authorized target")
            return True

        print_warning(f"No successful assoc (last status={assoc_seen['status']})")
        print_info("AP may be SAE-only, PMF-locked, or MAC filtered")
        return False