#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Parse WPA/RSN information elements into human-readable encryption labels."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

from lib.protocols.wlan.ie import RSN_IE, VENDOR_IE, WPA_OUI, RSN_OUI, iter_information_elements


AKM_PSK = 2
AKM_SAE = 8
AKM_PSK_SHA256 = 6
AKM_FT_PSK = 4
AKM_OWE = 18


@dataclass
class SecurityInfo:
    ssid: str = ""
    channel: int | None = None
    cipher: str = "unknown"
    akm_labels: list[str] = field(default_factory=list)
    pmf_required: bool = False
    hidden: bool = False
    wps: bool = False
    wpa3_transition: bool = False
    ft_psk: bool = False
    owe: bool = False
    pmf_capable: bool = False
    rsnxe_sae_h2e: bool = False
    rsnxe_wpa3_only: bool = False

    @property
    def encryption(self) -> str:
        if not self.akm_labels:
            return "OPEN" if self.cipher == "open" else self.cipher
        return "+".join(self.akm_labels)


def _oui_suite(body: bytes, offset: int) -> tuple[int, bytes]:
    if offset + 4 > len(body):
        return 0, b""
    oui = body[offset : offset + 3]
    suite = body[offset + 3]
    return suite, oui


def parse_wpa_vendor_ie(body: bytes) -> list[int]:
    if len(body) < 6 or body[0:3] != WPA_OUI or body[3:5] != b"\x01\x00":
        return []
    akms: list[int] = []
    pos = 6
    if pos + 2 > len(body):
        return akms
    pos += 2  # version
    pos += 4  # group cipher
    if pos + 2 > len(body):
        return akms
    n_pair = struct.unpack(">H", body[pos : pos + 2])[0]
    pos += 2 + 4 * n_pair
    if pos + 2 > len(body):
        return akms
    n_akm = struct.unpack(">H", body[pos : pos + 2])[0]
    pos += 2
    for _ in range(n_akm):
        if pos + 4 > len(body):
            break
        _, oui = _oui_suite(body, pos)
        if oui == WPA_OUI:
            akms.append(body[pos + 3])
        pos += 4
    return akms


def parse_rsn_ie(body: bytes) -> tuple[list[int], list[int], int]:
    """Return (group_cipher, pairwise_ciphers, akm_suites, caps)."""
    if len(body) < 2:
        return [], [], 0
    pos = 2  # version
    if pos + 4 > len(body):
        return [], [], 0
    pos += 4  # group
    akms: list[int] = []
    pairwise: list[int] = []
    if pos + 2 > len(body):
        return pairwise, akms, 0
    n_pair = struct.unpack(">H", body[pos : pos + 2])[0]
    pos += 2
    for _ in range(n_pair):
        if pos + 4 > len(body):
            break
        suite, oui = _oui_suite(body, pos)
        if oui == RSN_OUI:
            pairwise.append(suite)
        pos += 4
    if pos + 2 > len(body):
        return pairwise, akms, 0
    n_akm = struct.unpack(">H", body[pos : pos + 2])[0]
    pos += 2
    for _ in range(n_akm):
        if pos + 4 > len(body):
            break
        suite, oui = _oui_suite(body, pos)
        if oui == RSN_OUI:
            akms.append(suite)
        pos += 4
    caps = 0
    if pos + 2 <= len(body):
        caps = struct.unpack(">H", body[pos : pos + 2])[0]
    return pairwise, akms, caps


def akm_label(akm: int) -> str:
    return {
        1: "802.1X",
        AKM_PSK: "WPA2-PSK",
        3: "FT-802.1X",
        4: "FT-PSK",
        5: "802.1X-SHA256",
        AKM_PSK_SHA256: "WPA2-PSK-SHA256",
        AKM_SAE: "WPA3-SAE",
        18: "OWE",
    }.get(akm, f"AKM-{akm}")


def parse_beacon_security(ies: bytes, ssid: str) -> SecurityInfo:
    from lib.protocols.wlan.rsnxe import parse_rsnxe

    info = SecurityInfo(ssid=ssid)
    info.hidden = ssid == ""
    info.cipher = "open"
    rsnxe = parse_rsnxe(ies)
    if rsnxe:
        info.rsnxe_sae_h2e = rsnxe.sae_h2e
        info.rsnxe_wpa3_only = rsnxe.wpa3_only
    for tag, body, _ in iter_information_elements(ies):
        if tag == RSN_IE:
            _, akms, caps = parse_rsn_ie(body)
            info.cipher = "RSN"
            info.akm_labels = [akm_label(a) for a in akms]
            info.pmf_required = bool(caps & 0x0040)
            info.pmf_capable = bool(caps & 0x0080)
            info.wpa3_transition = AKM_SAE in akms and AKM_PSK in akms
            info.ft_psk = AKM_FT_PSK in akms
            info.owe = AKM_OWE in akms
        elif tag == VENDOR_IE and body[:3] == WPA_OUI:
            akms = parse_wpa_vendor_ie(body)
            if akms:
                info.cipher = "WPA"
                info.akm_labels = [akm_label(a) for a in akms]
        elif tag == VENDOR_IE and body[:4] == bytes.fromhex("0050f204"):
            info.wps = True
    return info