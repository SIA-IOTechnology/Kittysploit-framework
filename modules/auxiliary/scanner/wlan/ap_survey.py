#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Multi-channel WiFi survey with pure-Python 802.11 parsing."""

from __future__ import annotations

import platform

from kittysploit import *
from lib.protocols.wlan.wlan_client import Wlan_client


class Module(Auxiliary, Wlan_client):
    __info__ = {
        "name": "WiFi AP Survey (Pure Python)",
        "description": (
            "Channel-aware wireless survey: parses beacons/probes natively (no aircrack-ng), "
            "tracks BSSIDs, encryption, WPS, PMF, and OUI vendors."
        ),
        "author": ["KittySploit Team"],
        "tags": ["scanner", "wlan", "wifi", "802.11", "recon"],
        "references": ["https://attack.mitre.org/techniques/T1016/"],
        "attack": {
            "tactics": ["TA0007"],
            "techniques": ["T1016"],
            "prerequisites": [
                "Wireless adapter in monitor mode",
                "CAP_NET_RAW / administrator for capture",
            ],
        },
    }

    timeout = OptInteger(45, "Total capture time in seconds", required=False)
    dwell = OptInteger(3, "Seconds to listen per channel hop (when CHANNELS set)", required=False)
    channels = OptString(
        "",
        "Comma-separated channels to scan (empty = 2.4 GHz + common 5 GHz)",
        required=False,
    )
    five_ghz = OptBool(True, "Include 5 GHz channels when CHANNELS is empty", required=False)
    channel_hop = OptBool(
        True,
        "Hop channels on Linux (ioctl); disable to sniff on current channel only",
        required=False,
    )

    def check(self):
        return self.wlan_check_iface()

    def _channel_list(self) -> list[int]:
        raw = str(self.channels or "").strip()
        if raw:
            out: list[int] = []
            for part in raw.split(","):
                part = part.strip()
                if part.isdigit():
                    out.append(int(part))
            return out
        return self.wlan_default_channels(bool(self.five_ghz))

    def run(self):
        timeout = max(5, int(self.timeout or 45))
        dwell = max(1, int(self.dwell or 3))
        channel_list = self._channel_list()
        state = self.wlan_reset_scan_state()

        print_info(f"WiFi survey on {self.iface} ({timeout}s)")
        print_info("=" * 78)

        def on_frame(raw: bytes, rssi: int | None) -> None:
            beacon = self.wlan_parse_beacon(raw, rssi=rssi)
            if not beacon:
                return
            rec = self.wlan_register_beacon(beacon)
            if rssi is not None:
                rec.rssi = rssi
            label = rec.ssid if rec.ssid != "<hidden>" else "<hidden>"
            print_status(
                f"CH{beacon.channel or '?':>3} | {label:24} | {beacon.bssid} | "
                f"{rec.encryption:18} | {rec.vendor or 'unknown'}"
            )

        hop = bool(self.channel_hop) and platform.system() == "Linux"
        try:
            if len(channel_list) <= 1 or not hop:
                self.wlan_sniff(on_frame, timeout=float(timeout))
            else:
                per = float(min(dwell, max(1, timeout // max(1, len(channel_list)))))
                chs = self.wlan_scan_hop_order(channel_list)
                print_status(f"Channel plan: {len(chs)} channel(s), ~{per:.0f}s each")
                self.wlan_sniff_channels(on_frame, chs, dwell=per, hop=True)
        except PermissionError:
            print_error("Permission denied — enable monitor mode and run elevated.")
            return False
        except OSError as exc:
            print_error(f"Capture failed: {exc}")
            return False

        print_info("=" * 78)
        if not state.aps:
            print_warning("No access points parsed — check monitor mode and antennas.")
            return False

        rows = sorted(state.aps.values(), key=lambda ap: (-(ap.rssi or -100), ap.ssid))
        print_success(f"Survey complete: {len(rows)} access point(s)")
        for ap in rows:
            print_info(
                f"  {ap.ssid:24} {ap.bssid} ch={ap.channel or '?':>3} "
                f"rssi={ap.rssi if ap.rssi is not None else '?'} enc={ap.encryption} "
                f"wps={'Y' if ap.wps else 'N'} pmf={'Y' if ap.pmf else 'N'} "
                f"vendor={ap.vendor or '?'}"
            )
        return True