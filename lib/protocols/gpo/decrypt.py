#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Credential and secret decryption helpers for GPO analysis."""

from __future__ import annotations

from typing import Optional

try:
    from Crypto.Cipher import DES

    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


def decrypt_vnc_password(cipher_hex: str) -> Optional[str]:
    """Decrypt a VNC password stored as hex ciphertext."""
    if not cipher_hex or not CRYPTO_AVAILABLE:
        return None
    try:
        ciphertext = bytes.fromhex(cipher_hex.strip())
        key = bytes.fromhex("e84ad660c4721ae0")
        iv = bytes.fromhex("0000000000000000")
        cipher = DES.new(key, DES.MODE_CBC, iv)
        plain = cipher.decrypt(ciphertext)
        return plain.decode("latin-1", errors="ignore").rstrip("\x00")
    except Exception:
        return None
