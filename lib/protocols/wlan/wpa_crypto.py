#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""WPA/WPA2-PSK key derivation and EAPOL MIC verification (stdlib + cryptography CMAC)."""

from __future__ import annotations

import hashlib
import hmac
import string

from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.cmac import CMAC

from lib.protocols.wlan.eapol_const import AES_128_CMAC, HMAC_SHA1_AES, MIC_OFFSET

KCK_LEN = 16


def is_valid_psk(psk: str) -> bool:
    enc = psk.encode("utf-8", errors="ignore")
    return 8 <= len(enc) <= 63


def derive_pmk(psk: str, ssid: bytes) -> bytes:
    if len(psk) == 64 and all(c in string.hexdigits for c in psk):
        return bytes.fromhex(psk)
    return hashlib.pbkdf2_hmac("sha1", psk.encode("utf-8"), ssid, 4096, 32)


def prf(key: bytes, label: bytes, data: bytes, nbytes: int) -> bytes:
    out = b""
    i = 0
    while len(out) < nbytes:
        out += hmac.new(key, label + b"\x00" + data + bytes([i]), hashlib.sha1).digest()
        i += 1
    return out[:nbytes]


def derive_ptk(
    pmk: bytes, ap_mac: bytes, sta_mac: bytes, anonce: bytes, snonce: bytes, nbytes: int
) -> bytes:
    mac_block = min(ap_mac, sta_mac) + max(ap_mac, sta_mac)
    nonce_block = min(anonce, snonce) + max(anonce, snonce)
    return prf(pmk, b"Pairwise key expansion", mac_block + nonce_block, nbytes)


def eapol_mic_hmac_sha1(kck: bytes, eapol_payload_mic_zeroed: bytes) -> bytes:
    return hmac.new(kck, eapol_payload_mic_zeroed, hashlib.sha1).digest()[:16]


def eapol_mic_aes_cmac(kck: bytes, eapol_payload_mic_zeroed: bytes) -> bytes:
    cmac = CMAC(algorithms.AES(kck), backend=None)
    cmac.update(eapol_payload_mic_zeroed)
    return cmac.finalize()[:16]


def key_descriptor_version(eapol: bytes) -> int:
    if len(eapol) < 7:
        return 0
    key_info = int.from_bytes(eapol[5:7], "big")
    return key_info & 0x0007


def pmkid_from_psk(psk: str, ssid: bytes, ap_mac: bytes, sta_mac: bytes, sha256: bool = False) -> bytes:
    pmk = derive_pmk(psk, ssid)
    digest = hashlib.sha256 if sha256 else hashlib.sha1
    return hmac.new(pmk, b"PMK Name" + ap_mac + sta_mac, digest).digest()[:16]


def verify_eapol_mic(
    psk: str,
    ssid: bytes,
    ap_mac: bytes,
    sta_mac: bytes,
    anonce: bytes,
    snonce: bytes,
    eapol_full: bytes,
    expected_mic: bytes,
) -> bool:
    if len(eapol_full) < MIC_OFFSET + 16:
        return False
    pmk = derive_pmk(psk, ssid)
    kck = derive_ptk(pmk, ap_mac, sta_mac, anonce, snonce, KCK_LEN)
    zeroed = eapol_full[:MIC_OFFSET] + b"\x00" * 16 + eapol_full[MIC_OFFSET + 16 :]
    kd = key_descriptor_version(eapol_full)
    if kd == HMAC_SHA1_AES:
        mic = eapol_mic_hmac_sha1(kck, zeroed)
    elif kd == AES_128_CMAC:
        mic = eapol_mic_aes_cmac(kck, zeroed)
    else:
        return False
    return hmac.compare_digest(mic, expected_mic)