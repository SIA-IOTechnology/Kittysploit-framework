#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""WPA3 / transition-mode downgrade risk heuristics."""

from __future__ import annotations

from lib.protocols.wlan.rsn import SecurityInfo


def transition_mode(sec: SecurityInfo) -> bool:
    labels = {x.upper() for x in sec.akm_labels}
    return ("WPA3-SAE" in labels and "WPA2-PSK" in labels) or sec.wpa3_transition


def assess_wpa3_downgrade(sec: SecurityInfo) -> dict:
    """Score whether WPA2-PSK fallback is exposed alongside SAE."""
    trans = transition_mode(sec)
    psk_fallback = trans or "WPA2-PSK" in [x.upper() for x in sec.akm_labels]
    risk = "none"
    if trans and not sec.pmf_required:
        risk = "high"
    elif trans and sec.pmf_required:
        risk = "medium"
    elif psk_fallback and not trans:
        risk = "low"
    note = {
        "high": "Transition WPA3+WPA2 without mandatory PMF — WPA2 PSK downgrade path likely.",
        "medium": "Transition mode with PMF required on RSN — PSK clients may still exist.",
        "low": "WPA2-PSK only or SAE-only beacon profile.",
        "none": "No obvious WPA2 fallback beside SAE.",
    }[risk if trans or psk_fallback else "none"]
    return {
        "ssid": sec.ssid,
        "encryption": sec.encryption,
        "transition": trans,
        "pmf_required": sec.pmf_required,
        "wps": sec.wps,
        "psk_fallback": psk_fallback,
        "sae_advertised": "WPA3-SAE" in [x.upper() for x in sec.akm_labels],
        "wpa2_psk_advertised": "WPA2-PSK" in [x.upper() for x in sec.akm_labels],
        "risk": risk,
        "note": note,
    }