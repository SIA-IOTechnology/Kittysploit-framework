#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Optional
from kittysploit import *


class Module(Obfuscator):
    """Additive stream obfuscator - obfuscates C2 traffic by adding key bytes (mod 256)."""

    SUPPORTED_CLIENT_LANGUAGES = ["python"]

    __info__ = {
        "name": "Additive Stream Obfuscator",
        "description": "Adds a repeating key to each byte (mod 256). Symmetric encode/decode. Alternative to XOR for signature evasion.",
        "author": "KittySploit Team",
        "version": "1.0.0",
    }

    key = OptString("kittysploit", "Additive key (string, repeated over data)", True)

    def _key_bytes(self) -> bytes:
        raw = (str(self.key).strip() or "kittysploit").encode("utf-8", errors="replace")
        return raw if raw else b"k"

    def encode(self, data: bytes, offset: int = 0) -> bytes:
        """Add key bytes to each byte (mod 256). offset = stream position for correct key alignment."""
        if not data:
            return data
        key_bytes = self._key_bytes()
        out = bytearray(len(data))
        for i, b in enumerate(data):
            out[i] = (b + key_bytes[(offset + i) % len(key_bytes)]) % 256
        return bytes(out)

    def decode(self, data: bytes, offset: int = 0) -> bytes:
        """Subtract key bytes from each byte (mod 256). offset = stream position for correct key alignment."""
        if not data:
            return data
        key_bytes = self._key_bytes()
        out = bytearray(len(data))
        for i, b in enumerate(data):
            out[i] = (b - key_bytes[(offset + i) % len(key_bytes)]) % 256
        return bytes(out)

    def generate_client_code(self, language: str) -> Optional[str]:
        """Generate Python code that defines _obf_encode(d) and _obf_decode(d) with stream-position offsets."""
        if language != "python":
            return None
        key_val = (str(self.key).strip() or "kittysploit").replace("\\", "\\\\").replace("'", "\\'")
        return (
            f"_obf_kb=('{key_val}').encode()\n"
            "_obf_doff=[0]\n_obf_eoff=[0]\n"
            "def _obf_decode(d):\n"
            " o=_obf_doff[0];out=bytearray(len(d))\n"
            " for i,b in enumerate(d): out[i]=(b-_obf_kb[(o+i)%len(_obf_kb)])%256\n"
            " _obf_doff[0]+=len(d)\n return bytes(out)\n"
            "def _obf_encode(d):\n"
            " o=_obf_eoff[0];out=bytearray(len(d))\n"
            " for i,b in enumerate(d): out[i]=(b+_obf_kb[(o+i)%len(_obf_kb)])%256\n"
            " _obf_eoff[0]+=len(d)\n return bytes(out)\n"
        )
