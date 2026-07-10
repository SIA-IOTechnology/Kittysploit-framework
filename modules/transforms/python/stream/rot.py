#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Optional
from kittysploit import *


class Module(Transform):
    """ROT (Caesar) stream transform - shifts each byte by a fixed value (mod 256)."""

    SUPPORTED_CLIENT_LANGUAGES = ["python"]

    __info__ = {
        "name": "ROT Stream Transform",
        "description": "Shifts each byte by a fixed value (mod 256). Encode: add shift, decode: subtract. Simple Caesar-style obfuscation.",
        "author": "KittySploit Team",
        "version": "1.0.0",
    }

    shift = OptInteger(13, "Byte shift value (0-255), applied mod 256", True)

    def _shift_val(self) -> int:
        v = int(self.shift) if self.shift is not None else 13
        return max(0, min(255, v % 256))

    def encode(self, data: bytes, offset: int = 0) -> bytes:
        """Add shift to each byte (mod 256). offset is ignored (no stream state)."""
        if not data:
            return data
        s = self._shift_val()
        out = bytearray(len(data))
        for i, b in enumerate(data):
            out[i] = (b + s) % 256
        return bytes(out)

    def decode(self, data: bytes, offset: int = 0) -> bytes:
        """Subtract shift from each byte (mod 256)."""
        if not data:
            return data
        s = self._shift_val()
        out = bytearray(len(data))
        for i, b in enumerate(data):
            out[i] = (b - s) % 256
        return bytes(out)

    def generate_client_code(self, language: str) -> Optional[str]:
        """Generate Python code that defines _xf_encode(d) and _xf_decode(d)."""
        if language != "python":
            return None
        s = self._shift_val()
        return (
            f"_xf_shift={s}\n"
            "def _xf_decode(d):\n"
            " return bytes((b-_xf_shift)%256 for b in d)\n"
            "def _xf_encode(d):\n"
            " return bytes((b+_xf_shift)%256 for b in d)\n"
        )
