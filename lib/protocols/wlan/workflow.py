#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Recommended WLAN module chains for operators and agents."""

from __future__ import annotations

WLAN_WORKFLOWS: dict[str, list[str]] = {
    "recon": [
        "auxiliary/scanner/wlan/ap_survey",
        "auxiliary/scanner/wlan/beacon_scan",
        "auxiliary/scanner/wlan/client_enum",
        "auxiliary/scanner/wlan/wps_scan",
        "auxiliary/scanner/wlan/wpa3_transition_scan",
        "auxiliary/scanner/wlan/owe_scan",
        "auxiliary/scanner/wlan/ft_psk_scan",
        "auxiliary/scanner/wlan/enterprise_scan",
        "auxiliary/scanner/wlan/rsnxe_scan",
    ],
    "capture": [
        "auxiliary/scanner/wlan/handshake_capture",
        "auxiliary/scanner/wlan/handshake_to_hc22000",
        "auxiliary/wlan/pmkid_harvest",
    ],
    "attack": [
        "auxiliary/wlan/deauth_inject",
        "auxiliary/wlan/wps_pixie",
        "auxiliary/wlan/wps_pin_brute",
        "auxiliary/wlan/evil_twin_lure",
        "auxiliary/wlan/wpa3_psk_probe",
    ],
    "offline": [
        "auxiliary/wlan/pcap_analyze",
        "auxiliary/wlan/wpa_cpu_crack",
        "auxiliary/wlan/wep_cpu_crack",
    ],
    "wep": [
        "auxiliary/scanner/wlan/wep_iv_collect",
        "auxiliary/wlan/wep_cpu_crack",
        "auxiliary/wlan/wep_chopchop",
        "auxiliary/wlan/wep_replay_inject",
    ],
    "post": [
        "auxiliary/wlan/wlan_vault",
        "auxiliary/wlan/decloak_ssid",
    ],
}

WLAN_PSK_PIPELINE = [
    "auxiliary/scanner/wlan/handshake_to_hc22000",
    "auxiliary/wlan/wpa_cpu_crack",
    "auxiliary/wlan/wlan_vault",
]