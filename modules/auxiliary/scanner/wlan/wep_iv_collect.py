#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Passive WEP IV harvest (authorized monitoring)."""

from __future__ import annotations
import os
from kittysploit import *
from lib.protocols.wlan.wlan_client import Wlan_client


class Module(Auxiliary, Wlan_client):
    __info__ = {
        "name": "WiFi WEP IV Collector",
        "description": "Sniff unique WEP IVs from data frames and export JSON for offline crack.",
        "author": ["KittySploit Team"],
        "tags": ["scanner", "wlan", "wifi", "wep", "802.11"],
        "references": ["https://attack.mitre.org/techniques/T1040/"],
    }

    timeout = OptInteger(60, "Capture duration", required=False)
    bssid = OptString("", "Filter BSSID", required=False)
    channel = OptInteger(0, "Channel (0 = current)", required=False)
    output = OptString("", "Output JSON (auto if empty)", required=False)
    min_ivs = OptInteger(20, "Minimum unique IVs before success", required=False)

    def check(self):
        return self.wlan_check_iface()

    def run(self):
        timeout = max(5, int(self.timeout or 60))
        filt = str(self.bssid or "").strip().lower()
        ch = int(self.channel or 0)
        need = max(1, int(self.min_ivs or 20))
        if ch:
            self.wlan_set_channel(ch)

        self.wlan_wep_reset()
        print_info(f"WEP IV collect ({timeout}s)" + (f" filter {filt}" if filt else ""))

        def on_frame(raw: bytes, _rssi: int | None) -> None:
            from lib.protocols.wlan.wep import parse_wep_data

            sample = parse_wep_data(raw)
            if not sample:
                return
            if filt and sample.bssid.lower() != filt:
                return
            self.wlan_wep_store().add(sample)
            n = self.wlan_wep_store().count
            if n % 10 == 0:
                print_status(f"Unique IVs: {n}")

        try:
            self.wlan_sniff(on_frame, timeout=float(timeout))
        except (PermissionError, OSError) as exc:
            print_error(f"Sniff failed: {exc}")
            return False

        count = self.wlan_wep_store().count
        out = str(self.output or "").strip()
        if not out:
            stamp = "wep_ivs"
            if filt:
                stamp = f"wep_{filt.replace(':', '')}"
            out = os.path.abspath(f"{stamp}.json")

        self.wlan_wep_save_json(out)
        print_info("=" * 72)
        print_success(f"Saved {count} IV sample(s) → {out}")
        if count < need:
            print_warning(f"Fewer than {need} IVs — more traffic or time may be required")
            return False
        print_info("Crack: auxiliary/wlan/wep_cpu_crack with this JSON + wordlist")
        return True