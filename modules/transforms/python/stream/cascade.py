#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Cascade stream transform: multi-layer encoding (XOR + Additive + ROT) with a single master key.
Designed for strong C2 traffic obfuscation and signature evasion.
"""

from typing import Optional
from kittysploit import *


def _derive_key_bytes(key_str: str, min_len: int = 16) -> bytes:
    """Normalize key to bytes; ensure minimum length by repeating if needed."""
    k = (key_str or "").strip()
    if not k:
        k = "kittysploit_cascade_default"
    raw = k.encode("utf-8", errors="replace")
    if len(raw) < min_len:
        raw = (raw * ((min_len // len(raw)) + 1))[:min_len]
    return raw


class Module(Transform):
    """
    Cascade stream transform: XOR → Additive → ROT with one master key.
    Strong multi-layer obfuscation; encode/decode use stream offset for chunk alignment.
    """

    SUPPORTED_CLIENT_LANGUAGES = ["python"]

    __info__ = {
        "name": "Cascade Stream Transform",
        "description": "Multi-layer: XOR + Additive + ROT with a single master key. High obfuscation strength, stream-offset aware.",
        "author": "KittySploit Team",
        "version": "1.0.0",
    }

    key = OptString(
        "kittysploit_cascade_strong_key_change_me",
        "Master key (string; 16+ chars recommended). Used for XOR, additive and ROT.",
        True,
    )

    def _key_bytes(self) -> bytes:
        return _derive_key_bytes(str(self.key).strip() or "kittysploit_cascade_strong_key_change_me")

    def _rot_shift(self) -> int:
        kb = self._key_bytes()
        return sum(kb) % 256

    def encode(self, data: bytes, offset: int = 0) -> bytes:
        """Encode: XOR(key) → Add(key) → ROT(shift). offset = stream position for key alignment."""
        if not data:
            return data
        kb = self._key_bytes()
        shift = self._rot_shift()
        out = bytearray(len(data))
        for i, b in enumerate(data):
            pos = offset + i
            x = b ^ kb[pos % len(kb)]
            x = (x + kb[pos % len(kb)]) % 256
            x = (x + shift) % 256
            out[i] = x
        return bytes(out)

    def decode(self, data: bytes, offset: int = 0) -> bytes:
        """Decode: ROT⁻¹ → Subtract(key) → XOR(key). offset = stream position for key alignment."""
        if not data:
            return data
        kb = self._key_bytes()
        shift = self._rot_shift()
        out = bytearray(len(data))
        for i, b in enumerate(data):
            pos = offset + i
            x = (b - shift) % 256
            x = (x - kb[pos % len(kb)]) % 256
            x = x ^ kb[pos % len(kb)]
            out[i] = x
        return bytes(out)

    def generate_client_code(self, language: str) -> Optional[str]:
        """Generate Python code defining _xf_encode(d) and _xf_decode(d) with stream offsets."""
        if language != "python":
            return None
        kb = self._key_bytes()
        shift = self._rot_shift()
        # Emit key as bytes([...]) so client uses same derived key as server
        kb_repr = ",".join(str(b) for b in kb)
        return (
            f"_xf_kb=bytes([{kb_repr}])\n"
            "_xf_kl=len(_xf_kb)\n"
            f"_xf_rot={shift}\n"
            "_xf_doff=[0]\n_xf_eoff=[0]\n"
            "def _xf_decode(d):\n"
            " o=_xf_doff[0];out=bytearray(len(d))\n"
            " for i,b in enumerate(d):\n"
            "  p=o+i;x=(b-_xf_rot)%256;x=(x-_xf_kb[p%_xf_kl])%256;x^=_xf_kb[p%_xf_kl]\n"
            "  out[i]=x\n"
            " _xf_doff[0]+=len(d)\n return bytes(out)\n"
            "def _xf_encode(d):\n"
            " o=_xf_eoff[0];out=bytearray(len(d))\n"
            " for i,b in enumerate(d):\n"
            "  p=o+i;x=b^_xf_kb[p%_xf_kl];x=(x+_xf_kb[p%_xf_kl])%256;x=(x+_xf_rot)%256\n"
            "  out[i]=x\n"
            " _xf_eoff[0]+=len(d)\n return bytes(out)\n"
        )
