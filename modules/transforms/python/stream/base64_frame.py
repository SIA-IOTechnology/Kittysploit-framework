#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import struct
from typing import Optional
from kittysploit import *


FRAME_PREFIX = b"K64 "
FRAME_SUFFIX = b"\n"
MAX_FRAME_SIZE = 1024 * 1024


class Module(Transform):
    """Base64 framed stream transform."""

    SUPPORTED_CLIENT_LANGUAGES = ["python"]

    __info__ = {
        "name": "Base64 Frame Transform",
        "description": "Frames each C2 chunk as a length-prefixed Base64 line. Handles fragmented TCP reads.",
        "author": "KittySploit Team",
        "version": "1.0.0",
    }

    def __init__(self, framework=None):
        super().__init__(framework)
        self._decode_buffer = bytearray()

    def encode(self, data: bytes, offset: int = 0) -> bytes:
        """Encode one chunk as: b'K64 ' + base64(length + payload) + b'\\n'."""
        if not data:
            return data
        payload = struct.pack(">I", len(data)) + data
        return FRAME_PREFIX + base64.b64encode(payload) + FRAME_SUFFIX

    def decode(self, data: bytes, offset: int = 0) -> bytes:
        """Decode complete Base64 frames and buffer incomplete lines."""
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
            if payload_len > MAX_FRAME_SIZE or payload_len > len(raw) - 4:
                continue
            out.append(raw[4 : 4 + payload_len])

        return b"".join(out)

    def generate_client_code(self, language: str) -> Optional[str]:
        """Generate Python code that implements the same framed Base64 transform."""
        if language != "python":
            return None
        return (
            "import base64,struct\n"
            "_xf_buf=bytearray()\n"
            "def _xf_encode(d):\n"
            " if not d: return d\n"
            " return b'K64 '+base64.b64encode(struct.pack('>I',len(d))+d)+b'\\n'\n"
            "def _xf_decode(d):\n"
            " _xf_buf.extend(d)\n"
            " out=[]\n"
            " while True:\n"
            "  i=_xf_buf.find(b'\\n')\n"
            "  if i==-1: break\n"
            "  line=bytes(_xf_buf[:i]).strip(); del _xf_buf[:i+1]\n"
            "  if not line.startswith(b'K64 '): continue\n"
            "  try: raw=base64.b64decode(line[4:],validate=True)\n"
            "  except Exception: continue\n"
            "  if len(raw)<4: continue\n"
            "  ln=struct.unpack('>I',raw[:4])[0]\n"
            "  if ln<=1024*1024 and ln<=len(raw)-4: out.append(raw[4:4+ln])\n"
            " return b''.join(out)\n"
        )
