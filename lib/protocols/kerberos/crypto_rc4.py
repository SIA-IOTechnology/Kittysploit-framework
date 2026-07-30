#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Kerberos RC4-HMAC (etype 23) helpers — pycryptodome only."""

from __future__ import annotations

import os
import struct
from typing import Optional

try:
    from Cryptodome.Cipher import ARC4
    from Cryptodome.Hash import HMAC, MD4, MD5
except ImportError:  # pragma: no cover
    from Crypto.Cipher import ARC4
    from Crypto.Hash import HMAC, MD4, MD5


def nt_hash_from_password(password: str) -> bytes:
    """NT hash = MD4(UTF-16LE(password))."""
    data = str(password or "").encode("utf-16le")
    return MD4.new(data).digest()


def nt_hash_from_hex(nthash_hex: str) -> bytes:
    raw = str(nthash_hex or "").strip().replace(" ", "")
    if ":" in raw:
        # LM:NT or :NT
        raw = raw.split(":")[-1]
    if len(raw) != 32:
        raise ValueError("NT hash must be 32 hex chars")
    return bytes.fromhex(raw)


def rc4_hmac_encrypt(key: bytes, key_usage: int, plaintext: bytes, confounder: Optional[bytes] = None) -> bytes:
    """RFC 4757 encrypt → checksum(16) || ciphertext."""
    if len(key) != 16:
        raise ValueError("RC4 key must be 16 bytes (NT hash)")
    if confounder is None:
        confounder = os.urandom(8)
    if len(confounder) != 8:
        raise ValueError("confounder must be 8 bytes")
    ki = HMAC.new(key, struct.pack(">I", int(key_usage)), MD5).digest()
    cksum = HMAC.new(ki, confounder + plaintext, MD5).digest()
    ke = HMAC.new(ki, cksum, MD5).digest()
    return cksum + ARC4.new(ke).encrypt(confounder + plaintext)


def rc4_hmac_decrypt(key: bytes, key_usage: int, cipher: bytes) -> bytes:
    """RFC 4757 decrypt; returns plaintext without confounder."""
    if len(key) != 16:
        raise ValueError("RC4 key must be 16 bytes (NT hash)")
    if len(cipher) < 16:
        raise ValueError("cipher too short")
    cksum = cipher[:16]
    enc = cipher[16:]
    ki = HMAC.new(key, struct.pack(">I", int(key_usage)), MD5).digest()
    ke = HMAC.new(ki, cksum, MD5).digest()
    plain = ARC4.new(ke).decrypt(enc)
    if len(plain) < 8:
        raise ValueError("decrypted payload too short")
    confounder, payload = plain[:8], plain[8:]
    expect = HMAC.new(ki, confounder + payload, MD5).digest()
    if expect != cksum:
        raise ValueError("RC4-HMAC checksum mismatch (wrong key?)")
    return payload
