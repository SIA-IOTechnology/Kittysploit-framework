#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Crack WPA-PSK / PMKID hash lines on CPU (mode 22000 format, no external cracker)."""

from __future__ import annotations
from pathlib import Path
from kittysploit import *
from lib.protocols.wlan.wlan_wpa import Wlan_wpa


class Module(Auxiliary, Wlan_wpa):
    __info__ = {
        "name": "WiFi WPA CPU Cracker",
        "description": (
            "Pure-Python WPA/WPA2-PSK cracker for .22000 hash lines or KittySploit exports "
            "(PBKDF2 + MIC verification — no hashcat/aircrack)."
        ),
        "author": ["KittySploit Team"],
        "tags": ["wlan", "wifi", "crack", "wpa", "hc22000"],
        "references": ["https://attack.mitre.org/techniques/T1110.002/"],
    }

    hash_file = OptFile("", "Hashcat 22000 hash file (.22000 or .hc22000)", required=True)
    wordlist = OptFile("", "Wordlist path (optional if USE_SSID_VARIANTS)", required=False)
    use_ssid_variants = OptBool(True, "Seed wordlist with SSID mutations", required=False)
    max_passwords = OptInteger(0, "Stop after N passwords (0 = unlimited)", required=False)
    store_vault = OptBool(True, "Save found PSK to local WLAN vault", required=False)

    def check(self):
        path = str(self.hash_file or "").strip()
        if not path or not Path(path).is_file():
            print_error("HASH_FILE must point to an existing 22000 hash file")
            return False
        wl = str(self.wordlist or "").strip()
        if not wl and not bool(self.use_ssid_variants):
            print_error("Provide WORDLIST or enable USE_SSID_VARIANTS")
            return False
        if wl and not Path(wl).is_file():
            print_error(f"Wordlist not found: {wl}")
            return False
        return True

    def run(self):
        path = Path(str(self.hash_file))
        cracker = self.wlan_open_cracker(path)
        if not cracker.lines:
            print_error("No valid WPA* hash lines in file")
            return False

        passwords: list[str] = []
        wl = str(self.wordlist or "").strip()
        if wl:
            passwords.extend(self.wlan_iter_wordlist(wl))
        if bool(self.use_ssid_variants):
            for line in cracker.lines:
                passwords.extend(self.wlan_ssid_wordlist_variants(line.ssid))

        passwords = self.wlan_merge_wordlists(passwords)
        limit = int(self.max_passwords or 0)
        if limit > 0:
            passwords = passwords[:limit]

        print_info(f"Testing {len(passwords)} candidate password(s) against {len(cracker.lines)} hash line(s)")

        def progress(count: int, current: str) -> None:
            print_status(f"Tried {count} passwords (current: {current[:32]})")

        found = self.wlan_crack_hashes(path, passwords, on_progress=progress if passwords else None)
        if not found:
            print_warning("No password matched")
            return False

        for tag, pwd in found.items():
            print_success(f"KEY FOUND [{tag}]: {pwd}")
            if bool(self.store_vault):
                for line in cracker.lines:
                    if tag != f"{line.mac_ap}:{line.essid}":
                        continue
                    bssid = ":".join(
                        line.mac_ap[i : i + 2] for i in range(0, min(12, len(line.mac_ap)), 2)
                    )
                    self.wlan_vault_store(
                        ssid=line.ssid,
                        bssid=bssid,
                        secret_type="psk",
                        secret=pwd,
                        hash_file=str(path),
                        nickname=f"{line.ssid}-cracked",
                    )
                    print_success("Stored PSK in ~/.kittysploit/wlan_vault.json")
                    break
        return True