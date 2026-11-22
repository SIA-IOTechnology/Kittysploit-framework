#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""802.11r Fast Transition (FT) beacon / EAPOL helpers."""

from __future__ import annotations

from dataclasses import dataclass

from lib.protocols.wlan.ie import iter_information_elements
from lib.protocols.wlan.owe import parse_mobility_domain
from lib.protocols.wlan.rsn import SecurityInfo

AKM_FT_PSK = 4
AKM_FT_8021X = 3
_FT_KEYINFO = 0x0020


@dataclass
class FtProfile:
    bssid: str
    ssid: str
    ft_psk: bool
    ft_8021x: bool
    mobility_domain: int | None
    rsn_ft_over_ds: bool
    rsn_ft_over_air: bool


def parse_rsn_ft_caps(ies: bytes) -> tuple[bool, bool]:
    for tag, body, _ in iter_information_elements(ies):
        if tag != 48 or len(body) < 8:
            continue
        pos = 2 + 4
        if pos + 2 > len(body):
            return False, False
        n_pair = int.from_bytes(body[pos : pos + 2], "big")
        pos += 2 + 4 * n_pair
        if pos + 2 > len(body):
            return False, False
        n_akm = int.from_bytes(body[pos : pos + 2], "big")
        pos += 2 + 4 * n_akm
        if pos + 2 > len(body):
            return False, False
        caps = int.from_bytes(body[pos : pos + 2], "big")
        over_ds = bool(caps & 0x0008)
        over_air = bool(caps & 0x0010)
        return over_ds, over_air
    return False, False


def assess_ft_beacon(ies: bytes, sec: SecurityInfo, bssid: str) -> FtProfile:
    akms = {x.upper() for x in sec.akm_labels}
    md = parse_mobility_domain(ies)
    over_ds, over_air = parse_rsn_ft_caps(ies)
    return FtProfile(
        bssid=bssid,
        ssid=sec.ssid,
        ft_psk="FT-PSK" in akms,
        ft_8021x="FT-802.1X" in akms,
        mobility_domain=md,
        rsn_ft_over_ds=over_ds,
        rsn_ft_over_air=over_air,
    )


def eapol_is_fast_transition(key_info: int) -> bool:
    return bool(key_info & _FT_KEYINFO)


def ft_export_supported(key_info: int) -> bool:
    """Standard PBKDF2 crack does not apply to FT-PSK exchanges."""
    return not eapol_is_fast_transition(key_info)