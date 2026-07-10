#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import struct
import zlib
from typing import Optional
from kittysploit import *


FRAME_PREFIX = b"KZ64 "
FRAME_SUFFIX = b"\n"
MAX_FRAME_SIZE = 1024 * 1024


class Module(Transform):
    """Compressed Base64 framed stream transform."""

    SUPPORTED_CLIENT_LANGUAGES = ["python"]

    __info__ = {
        "name": "Zlib Base64 Frame Transform",
        "description": "Compresses each C2 chunk with zlib, then frames it as a length-prefixed Base64 line.",
        "author": "KittySploit Team",
        "version": "1.0.0",
    }

    compression_level = OptInteger(6, "zlib compression level (0-9)", False, advanced=True)

    def __init__(self, framework=None):
        super().__init__(framework)
        self._decode_buffer = bytearray()

    def _level(self) -> int:
        try:
            value = int(self.compression_level)
        except Exception:
            value = 6
        return max(0, min(9, value))

    def encode(self, data: bytes, offset: int = 0) -> bytes:
        """Encode one chunk as: b'KZ64 ' + base64(raw_len + zlib(payload)) + b'\\n'."""
        if not data:
            return data
        compressed = zlib.compress(data, self._level())
        payload = struct.pack(">I", len(data)) + compressed
        return FRAME_PREFIX + base64.b64encode(payload) + FRAME_SUFFIX

    def decode(self, data: bytes, offset: int = 0) -> bytes:
        """Decode complete compressed Base64 frames and buffer incomplete lines."""
        if not data:
            return data
        self._decode_buffer.extend(data)
        out = []

        while True:
            newline = self._decode_buffer.find(FRAME_SUFFIX)
            if newline == -1:
                break

            line = bytes(self._decode_buffer[:newline]).strip()
            del self._decode_buffer[: newline + 1]

            if not line.startswith(FRAME_PREFIX):
                continue
            try:
                raw = base64.b64decode(line[len(FRAME_PREFIX):], validate=True)
            except Exception:
                continue
            if len(raw) < 4:
                continue

            payload_len = struct.unpack(">I", raw[:4])[0]
            if payload_len > MAX_FRAME_SIZE:
                continue
            try:
                payload = zlib.decompress(raw[4:])
            except Exception:
                continue
            if len(payload) != payload_len:
                continue
            out.append(payload)

        return b"".join(out)

    def generate_client_code(self, language: str) -> Optional[str]:
        """Generate Python code that implements the same zlib + Base64 framing."""
        if language != "python":
            return None
        level = self._level()
        return (
            "import base64,struct,zlib\n"
            f"_xf_zlevel={level}\n"
            "_xf_buf=bytearray()\n"
            "def _xf_encode(d):\n"
            " if not d: return d\n"
            " c=zlib.compress(d,_xf_zlevel)\n"
            " return b'KZ64 '+base64.b64encode(struct.pack('>I',len(d))+c)+b'\\n'\n"
            "def _xf_decode(d):\n"
            " _xf_buf.extend(d)\n"
            " out=[]\n"
            " while True:\n"
            "  i=_xf_buf.find(b'\\n')\n"
            "  if i==-1: break\n"
            "  line=bytes(_xf_buf[:i]).strip(); del _xf_buf[:i+1]\n"
            "  if not line.startswith(b'KZ64 '): continue\n"
            "  try: raw=base64.b64decode(line[5:],validate=True)\n"
            "  except Exception: continue\n"
            "  if len(raw)<4: continue\n"
            "  ln=struct.unpack('>I',raw[:4])[0]\n"
            "  if ln>1024*1024: continue\n"
            "  try: p=zlib.decompress(raw[4:])\n"
            "  except Exception: continue\n"
            "  if len(p)==ln: out.append(p)\n"
            " return b''.join(out)\n"
        )
