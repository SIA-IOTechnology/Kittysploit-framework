#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Favicon hashing helpers (Shodan-compatible MurmurHash3 x86 32-bit)."""

from __future__ import annotations

import base64
import hashlib
import struct
from typing import Dict


def _mmh3_x86_32(data: bytes, seed: int = 0) -> int:
    """Pure-Python MurmurHash3 x86 32-bit (Shodan favicon hash)."""
    length = len(data)
    nblocks = length // 4
    h1 = seed & 0xFFFFFFFF
    c1 = 0xCC9E2D51
    c2 = 0x1B873593

    for i in range(nblocks):
        k1 = struct.unpack_from("<I", data, i * 4)[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

    tail = data[nblocks * 4 :]
    k1 = 0
    if len(tail) >= 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if len(tail) >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    if h1 & 0x80000000:
        return int(h1 - 0x100000000)
    return int(h1)


def favicon_hashes(data: bytes) -> Dict[str, str]:
    """Return MD5, SHA256, and Shodan-style MurmurHash3 favicon hashes."""
    if not data:
        return {"md5": "", "sha256": "", "mmh3": "", "mmh3_b64": ""}
    mmh3_val = _mmh3_x86_32(data)
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "mmh3": str(mmh3_val),
        "mmh3_b64": base64.encodebytes(
            struct.pack("<i", mmh3_val)
        ).decode().strip(),
    }
