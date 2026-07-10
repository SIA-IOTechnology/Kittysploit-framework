#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Optional
from kittysploit import *


class Module(Transform):
    """XOR stream transform - obfuscates C2 traffic with a repeating XOR key."""

    SUPPORTED_CLIENT_LANGUAGES = ["python"]

    __info__ = {
        "name": "XOR Stream Transform",
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
        """Generate Python code that defines _xf_encode(d) and _xf_decode(d) with stream-position offsets."""
        if language != "python":
            return None
        key_val = (str(self.key).strip() or "kittysploit").replace("\\", "\\\\").replace("'", "\\'")
        return (
            f"_xf_kb=('{key_val}').encode()\n"
            "_xf_doff=[0]\n_xf_eoff=[0]\n"
            "def _xf_decode(d):\n"
            " o=_xf_doff[0];out=bytearray(len(d))\n"
            " for i,b in enumerate(d): out[i]=b^_xf_kb[(o+i)%len(_xf_kb)]\n"
            " _xf_doff[0]+=len(d)\n return bytes(out)\n"
            "def _xf_encode(d):\n"
            " o=_xf_eoff[0];out=bytearray(len(d))\n"
            " for i,b in enumerate(d): out[i]=b^_xf_kb[(o+i)%len(_xf_kb)]\n"
            " _xf_eoff[0]+=len(d)\n return bytes(out)\n"
        )
