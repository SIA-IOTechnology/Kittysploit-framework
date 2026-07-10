#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Optional
from kittysploit import *


class Module(Obfuscator):
    """XOR stream obfuscator - obfuscates C2 traffic with a repeating XOR key."""

    SUPPORTED_CLIENT_LANGUAGES = ["python"]

    __info__ = {
        "name": "XOR Stream Obfuscator",
        "description": "XORs the C2 stream with a repeating key. Symmetric encode/decode. Evades simple signature detection.",
        "author": "KittySploit Team",
        "version": "1.0.0",
    }

    key = OptString("kittysploit", "XOR key (string, repeated over data)", True)

    def encode(self, data: bytes, offset: int = 0) -> bytes:
        """XOR data with the key (repeating). offset = stream position for correct key alignment."""
        if not data:
            return data
        key_bytes = (str(self.key).strip() or "kittysploit").encode("utf-8", errors="replace")
        if not key_bytes:
            return data
        out = bytearray(len(data))
        for i, b in enumerate(data):
            out[i] = b ^ key_bytes[(offset + i) % len(key_bytes)]
        return bytes(out)

    def decode(self, data: bytes, offset: int = 0) -> bytes:
        """XOR is symmetric: decode = encode."""
        return self.encode(data, offset)

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
            " for i,b in enumerate(d): out[i]=b^_obf_kb[(o+i)%len(_obf_kb)]\n"
            " _obf_doff[0]+=len(d)\n return bytes(out)\n"
            "def _obf_encode(d):\n"
            " o=_obf_eoff[0];out=bytearray(len(d))\n"
            " for i,b in enumerate(d): out[i]=b^_obf_kb[(o+i)%len(_obf_kb)]\n"
            " _obf_eoff[0]+=len(d)\n return bytes(out)\n"
        )
