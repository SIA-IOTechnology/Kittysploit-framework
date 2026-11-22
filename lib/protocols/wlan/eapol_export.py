#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Pick hashcat 22000 message_pair + EAPOL material from tracked 4-way messages."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from lib.protocols.wlan.eapol_const import MIC_LEN, NONCE_LEN
from lib.protocols.wlan.ft import ft_export_supported

if TYPE_CHECKING:
    from lib.protocols.wlan.handshake_tracker import EapolKeyMessage

_ZERO_NONCE = b"\x00" * NONCE_LEN
_MIN_EAPOL_KEY = MIC_LEN + 81


@dataclass(frozen=True)
class ExportCandidate:
    message_pair: str
    anonce: bytes
    eapol_key: bytes
    mic: bytes
    label: str


def _valid_m2(msg: EapolKeyMessage | None) -> bool:
    if msg is None:
        return False
    return len(msg.eapol_key) >= _MIN_EAPOL_KEY and msg.mic != b"\x00" * MIC_LEN


def _anonce_from_m1(m1: EapolKeyMessage | None, fallback: bytes) -> bytes:
    if m1 and m1.anonce and m1.anonce != _ZERO_NONCE:
        return m1.anonce
    if m1 and len(m1.eapol_key) >= 17 + NONCE_LEN:
        nonce = m1.eapol_key[17 : 17 + NONCE_LEN]
        if nonce != _ZERO_NONCE:
            return nonce
    return fallback


def select_eapol_export(messages: dict[int, EapolKeyMessage]) -> ExportCandidate | None:
    """
    Prefer M1+M2 (pair 02), then M2+M3 (01), M1+M4 (04), lone M2 with ANonce (00).
    """
    for msg in messages.values():
        if not ft_export_supported(msg.key_info):
            return None

    m1 = messages.get(1)
    m2 = messages.get(2)
    m3 = messages.get(3)
    m4 = messages.get(4)

    if _valid_m2(m2) and (m1 or any(m2.anonce)):
        anonce = _anonce_from_m1(m1, m2.anonce if m2.anonce != _ZERO_NONCE else _ZERO_NONCE)
        pair = "02" if anonce != _ZERO_NONCE else "00"
        return ExportCandidate(
            message_pair=pair,
            anonce=anonce,
            eapol_key=m2.eapol_key,
            mic=m2.mic,
            label=f"M1+M2 ({pair})",
        )

    if _valid_m2(m3) and _valid_m2(m2):
        anonce = _anonce_from_m1(m1, m2.snonce if any(m2.snonce) else _ZERO_NONCE)
        return ExportCandidate(
            message_pair="01",
            anonce=anonce,
            eapol_key=m3.eapol_key,
            mic=m3.mic,
            label="M2+M3 (01)",
        )

    if _valid_m2(m4) and m1:
        anonce = _anonce_from_m1(m1, _ZERO_NONCE)
        return ExportCandidate(
            message_pair="04",
            anonce=anonce,
            eapol_key=m4.eapol_key,
            mic=m4.mic,
            label="M1+M4 (04)",
        )

    if _valid_m2(m2):
        return ExportCandidate(
            message_pair="00",
            anonce=_ZERO_NONCE,
            eapol_key=m2.eapol_key,
            mic=m2.mic,
            label="M2-only (00)",
        )
    return None