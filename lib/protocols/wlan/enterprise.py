#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""802.1X / enterprise WLAN beacon assessment."""

from __future__ import annotations

from dataclasses import dataclass

from lib.protocols.wlan.rsn import SecurityInfo


@dataclass
class EnterpriseProfile:
    bssid: str
    ssid: str
    eap_8021x: bool
    ft_8021x: bool
    psk_also: bool
    pmf_required: bool
    note: str


def assess_enterprise(sec: SecurityInfo, bssid: str) -> EnterpriseProfile:
    labels = {x.upper() for x in sec.akm_labels}
    eap = "802.1X" in labels or "802.1X-SHA256" in labels
    ft_eap = "FT-802.1X" in labels
    psk = "WPA2-PSK" in labels or "FT-PSK" in labels
    note = "open or unknown"
    if eap and psk:
        note = "mixed enterprise + PSK — check VLAN / ACL separation"
    elif eap:
        note = "enterprise EAP only — capture EAPOL for offline analysis"
    elif psk:
        note = "PSK network"
    return EnterpriseProfile(
        bssid=bssid,
        ssid=sec.ssid,
        eap_8021x=eap,
        ft_8021x=ft_eap,
        psk_also=psk,
        pmf_required=sec.pmf_required,
        note=note,
    )