#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Offline PCAP/PCAPNG analysis: AP table, handshakes, PMKID → 22000 export."""

from __future__ import annotations
from pathlib import Path
from kittysploit import *
from lib.protocols.wlan.wlan_client import Wlan_client


class Module(Auxiliary, Wlan_client):
    __info__ = {
        "name": "WiFi PCAP Analyzer (Pure Python)",
        "description": (
            "Parse 802.11 captures without tshark/aircrack: enumerate APs, extract "
            "crackable WPA handshakes/PMKIDs, write .hc22000 for auxiliary/wlan/wpa_cpu_crack."
        ),
        "author": ["KittySploit Team"],
        "tags": ["wlan", "wifi", "pcap", "hc22000", "forensics"],
        "references": ["https://attack.mitre.org/techniques/T1040/"],
    }

    pcap = OptFile("", "Input PCAP or PCAPNG file", required=True)
    hc22000_out = OptString(
        "",
        "Output .hc22000 path (empty = <pcap>.hc22000 next to input)",
        required=False,
    )
    export_pcap = OptString(
        "",
        "Optional PCAP path for captured handshake frames only",
        required=False,
    )

    def check(self):
        path = str(self.pcap or "").strip()
        if not path or not Path(path).is_file():
            print_error("PCAP file required")
            return False
        return True

    def run(self):
        src = Path(str(self.pcap))
        state = self.wlan_reset_scan_state()
        self.wlan_reset_handshake_tracker()
        ssid_by_bssid: dict[str, str] = {}
        handshake_frames: list[bytes] = []

        count = 0
        for raw in self.wlan_iter_pcap(src):
            count += 1
            beacon = self.wlan_parse_beacon(raw)
            if beacon:
                self.wlan_note_beacon_ssid(beacon, ssid_by_bssid)
                state.upsert_ap(self.wlan_ap_from_beacon(beacon))
            eap = self.wlan_parse_eapol(raw)
            if eap:
                handshake_frames.append(raw)
                self.wlan_track_parsed_eapol(eap, ssid_by_bssid)

        lines = self.wlan_export_hc22000(ssid_by_bssid)
        out_hc = str(self.hc22000_out or "").strip() or str(src.with_suffix(".hc22000"))

        print_info(f"Parsed {count} link-layer frame(s) from {src}")
        print_info("=" * 72)
        for ap in sorted(state.aps.values(), key=lambda a: a.ssid):
            print_info(
                f"  {ap.ssid:24} {ap.bssid} enc={ap.encryption} vendor={ap.vendor or '?'}"
            )

        for row in self.wlan_handshake_summaries():
            if row.get("fast_transition"):
                print_warning(
                    f"  FT skip {row['bssid']} ↔ {row['station']} ({row['messages']})"
                )
            elif row.get("exportable"):
                print_info(
                    f"  Handshake {row['bssid']} ↔ {row['station']} | "
                    f"{row['messages']} pair={row.get('message_pair')}"
                )

        if lines:
            self.wlan_write_hc22000(out_hc, lines)
            print_success(f"Wrote {len(lines)} hash line(s) to {out_hc}")
        else:
            print_warning("No crackable WPA artifacts found in capture")

        export_path = str(self.export_pcap or "").strip()
        if export_path and handshake_frames:
            self.wlan_write_pcap(export_path, handshake_frames)
            print_success(f"Exported {len(handshake_frames)} EAPOL frame(s) to {export_path}")

        return bool(lines or state.aps)