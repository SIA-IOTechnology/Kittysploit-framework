#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""WEP ARP replay / chop helpers (lab replay with rotated IV)."""

from __future__ import annotations

import os

from lib.protocols.wlan.mac import mac_header, str_to_mac
from lib.protocols.wlan.wep import parse_wep_data
from lib.protocols.wlan.wep_crypto import rc4_crypt, wep_crc, wep_seed, wep_unwrap


def rotate_iv(iv: bytes) -> bytes:
    val = int.from_bytes(iv, "big") + 1
    return val.to_bytes(3, "big")


def build_wep_data_frame(
    bssid: str,
    sta: str,
    iv: bytes,
    key_id: int,
    plaintext: bytes,
    key: bytes,
    *,
    to_ds: bool = True,
) -> bytes:
    body_payload = plaintext + wep_crc(plaintext)
    encrypted = rc4_crypt(wep_seed(iv, key), body_payload)
    wep_body = iv + bytes([key_id & 0x03]) + encrypted
    bssid_b = str_to_mac(bssid)
    sta_b = str_to_mac(sta)
    if to_ds:
        fc = bytes([0x08, 0x41])
        hdr = mac_header(fc, bssid_b, sta_b, bssid_b)
    else:
        fc = bytes([0x08, 0x42])
        hdr = mac_header(fc, sta_b, bssid_b, bssid_b)
    return hdr + wep_body


def wep_chopchop_try(sample_iv: bytes, cipher: bytes, key: bytes, byte_pos: int) -> bytes | None:
    """Try single-byte chop at encrypted position (oracle via ICV)."""
    if byte_pos < 0 or byte_pos >= len(cipher) - 4:
        return None
    trial = bytearray(cipher)
    for guess in range(256):
        trial[byte_pos] = guess
        if wep_unwrap(sample_iv, bytes(trial), key):
            return bytes([guess])
    return None


def replay_from_capture(frame: bytes, key: bytes, new_iv: bytes | None = None) -> bytes | None:
    sample = parse_wep_data(frame)
    if not sample:
        return None
    plain = wep_unwrap(sample.iv, sample.ciphertext, key)
    if not plain:
        return None
    iv = new_iv or rotate_iv(sample.iv)
    return build_wep_data_frame(
        sample.bssid,
        sample.station,
        iv,
        sample.key_id,
        plain,
        key,
        to_ds=True,
    )


def random_iv() -> bytes:
    return os.urandom(3)