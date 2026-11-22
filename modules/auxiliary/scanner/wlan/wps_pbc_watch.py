#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Passive WPS Push-Button (PBC) session watcher on the air."""

from __future__ import annotations
from kittysploit import *
from lib.protocols.wlan.wlan_client import Wlan_client
from lib.protocols.wlan.wsc import dev_password_label, wsc_message_carries_pbc


class Module(Auxiliary, Wlan_client):
    __info__ = {
        "name": "WiFi WPS PBC Watcher",
        "description": (
            "Sniff EAP-WSC frames and alert when Device Password ID indicates "
            "Push-Button (PBC) mode on an access point (passive only)."
        ),
        "author": ["KittySploit Team"],
        "tags": ["scanner", "wlan", "wifi", "wps", "pbc", "802.11"],
        "references": ["https://attack.mitre.org/techniques/T1040/"],
    }

    timeout = OptInteger(120, "Listen duration (seconds)", required=False)
    bssid = OptString("", "Filter BSSID (optional)", required=False)

    def check(self):
        return self.wlan_check_iface()

    def run(self):
        duration = max(10, int(self.timeout or 120))
        filt = str(self.bssid or "").strip().lower()
        seen: set[str] = set()

        print_info(f"WPS PBC watcher on {self.iface} ({duration}s)")
        print_info("=" * 72)

        def on_frame(raw: bytes, rssi: int | None) -> None:
            stripped = self.wlan_strip_radiotap(raw)
            msg = self.wlan_parse_wsc_eapol(stripped)
            if not msg:
                return
            if not wsc_message_carries_pbc(msg):
                return
            ap = self.wlan_dot11_bssid(stripped) or "?"
            if filt and ap.lower() != filt:
                return
            key = f"{ap}:{msg.msg_type}"
            if key in seen:
                return
            seen.add(key)
            dev = msg.dev_password_id()
            label = dev_password_label(dev)
            print_success(
                f"PBC session | AP {ap} | WSC msg {msg.msg_type} | "
                f"dev_password={label} | rssi={rssi if rssi is not None else '?'}"
            )

        try:
            self.wlan_sniff(on_frame, timeout=float(duration))
        except (PermissionError, OSError) as exc:
            print_error(f"Sniff failed: {exc}")
            return False

        if not seen:
            print_warning("No PBC WSC frames observed (user may not have pressed WPS)")
        else:
            print_info(f"Observed {len(seen)} PBC-related WSC event(s)")
        return True