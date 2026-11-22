#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""WEP RC4 + ICV (CRC32) helpers."""

from __future__ import annotations

import struct
from zlib import crc32


def _rc4_ksa(key: bytes) -> list[int]:
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    return s


def rc4_crypt(key: bytes, data: bytes) -> bytes:
    s = _rc4_ksa(key)
    i = j = 0
    out = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        k = s[(s[i] + s[j]) % 256]
        out.append(byte ^ k)
    return bytes(out)


def wep_seed(iv: bytes, key: bytes) -> bytes:
    return iv + key


def wep_crc(data: bytes) -> bytes:
    val = crc32(data) & 0xFFFFFFFF
    return struct.pack("<I", val)[:3]


def wep_unwrap(iv: bytes, cipher: bytes, key: bytes) -> bytes | None:
    """Decrypt WEP payload and validate 3-byte ICV."""
    if len(iv) != 3 or len(cipher) < 4:
        return None
    plain = rc4_crypt(wep_seed(iv, key), cipher)
    body, icv = plain[:-4], plain[-4:]
    expect = wep_crc(body)
    if icv[:3] != expect:
        return None
    return body


def wep_key_candidates(passphrase: str, *, len_128: bool = False) -> list[bytes]:
    raw = passphrase.encode("latin-1", errors="ignore")
    if len_128:
        if len(raw) == 13:
            return [raw]
        if len(raw) == 26 and all(c in "0123456789abcdefABCDEF" for c in passphrase):
            try:
                return [bytes.fromhex(passphrase)]
            except ValueError:
                pass
        return []
    if len(raw) == 5:
        return [raw]
    if len(raw) == 10 and all(c in "0123456789abcdefABCDEF" for c in passphrase):
        try:
            return [bytes.fromhex(passphrase)]
        except ValueError:
            pass
    return []