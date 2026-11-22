#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""WEP chopchop: local ICV oracle and injectable chopped frames."""

from __future__ import annotations

from lib.protocols.wlan.wep import WepSample
from lib.protocols.wlan.wep_crypto import wep_unwrap
from lib.protocols.wlan.wep_replay import build_wep_data_frame, rotate_iv


def chop_tail_byte(cipher: bytes) -> bytes:
    """Drop last ciphertext byte (chop step before ICV)."""
    if len(cipher) < 5:
        return cipher
    return cipher[:-1]


def try_chop_guess(sample: WepSample, key: bytes, position: int, guess: int) -> bool:
    """Return True if ICV still validates after replacing ciphertext byte."""
    if position < 0 or position >= len(sample.ciphertext):
        return False
    trial = bytearray(sample.ciphertext)
    trial[position] = guess & 0xFF
    return wep_unwrap(sample.iv, bytes(trial), key) is not None


def peel_plaintext_local(sample: WepSample, key: bytes) -> bytes | None:
    """Decrypt full payload when key is known (validates chop path)."""
    return wep_unwrap(sample.iv, sample.ciphertext, key)


def build_chop_inject_frame(
    sample: WepSample,
    key: bytes,
    *,
    chop_index: int | None = None,
    new_iv: bytes | None = None,
) -> bytes | None:
    """
    Build a shorter WEP frame after successful local unwrap + chop.
    ``chop_index`` is plaintext length after chop.
    """
    plain = wep_unwrap(sample.iv, sample.ciphertext, key)
    if not plain or len(plain) < 2:
        return None
    if chop_index is None:
        chop_index = len(plain) - 1
    chop_index = max(1, min(chop_index, len(plain)))
    chopped = plain[:chop_index]
    iv = new_iv or rotate_iv(sample.iv)
    return build_wep_data_frame(
        sample.bssid,
        sample.station,
        iv,
        sample.key_id,
        chopped,
        key,
        to_ds=True,
    )