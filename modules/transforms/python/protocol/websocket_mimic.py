#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
WebSocket mimic transform.

The first server-side encode prepends an HTTP 101 response, generated client
code prepends an HTTP Upgrade request, then traffic is wrapped in binary
WebSocket frames. Server frames are unmasked; generated client frames are masked
to resemble browser/client WebSocket traffic.
"""

import os
from typing import Optional
from kittysploit import *


MAX_FRAME_SIZE = 65535
MAX_BUFFER_SIZE = 1024 * 1024
HEADER_END = b"\r\n\r\n"

SERVER_UPGRADE = (
    b"HTTP/1.1 101 Switching Protocols\r\n"
    b"Upgrade: websocket\r\n"
    b"Connection: Upgrade\r\n"
    b"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
    b"\r\n"
)

CLIENT_UPGRADE = (
    b"GET /socket.io/?transport=websocket HTTP/1.1\r\n"
    b"Host: update.local\r\n"
    b"Upgrade: websocket\r\n"
    b"Connection: Upgrade\r\n"
    b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
    b"Sec-WebSocket-Version: 13\r\n"
    b"\r\n"
)


class Module(Transform):
    """WebSocket binary frame mimic transform."""

    SUPPORTED_CLIENT_LANGUAGES = ["python"]

    __info__ = {
        "name": "WebSocket Mimic Transform",
        "description": "Wraps C2 bytes in WebSocket-like binary frames with an initial HTTP Upgrade exchange.",
        "author": "KittySploit Team",
        "version": "1.0.0",
    }

    def __init__(self, framework=None):
        super().__init__(framework)
        self._decode_buffer = bytearray()
        self._first_encode_done = False

    def _frame(self, payload: bytes, masked: bool = False) -> bytes:
        if len(payload) > MAX_FRAME_SIZE:
            payload = payload[:MAX_FRAME_SIZE]
        first = 0x82  # FIN + binary opcode
        length = len(payload)
        if length < 126:
            header = bytes([first, (0x80 if masked else 0) | length])
        else:
            header = bytes([first, (0x80 if masked else 0) | 126, (length >> 8) & 0xFF, length & 0xFF])
        if not masked:
            return header + payload
        mask = os.urandom(4)
        masked_payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        return header + mask + masked_payload

    def encode(self, data: bytes, offset: int = 0) -> bytes:
        if not data:
            return data
        out = []
        if not self._first_encode_done:
            out.append(SERVER_UPGRADE)
            self._first_encode_done = True
        remaining = data
        while remaining:
            chunk = remaining[:MAX_FRAME_SIZE]
            remaining = remaining[MAX_FRAME_SIZE:]
            out.append(self._frame(chunk, masked=False))
        return b"".join(out)

    def _skip_http_headers_if_present(self) -> bool:
        if not self._decode_buffer.startswith((b"HTTP/", b"GET ", b"POST ")):
            return True
        end = self._decode_buffer.find(HEADER_END)
        if end == -1:
            if len(self._decode_buffer) > 8192:
                self._decode_buffer.clear()
            return False
        del self._decode_buffer[: end + len(HEADER_END)]
        return True

    def decode(self, data: bytes, offset: int = 0) -> bytes:
        if not data:
            return data
        self._decode_buffer.extend(data)
        if len(self._decode_buffer) > MAX_BUFFER_SIZE:
            del self._decode_buffer[:-MAX_BUFFER_SIZE]

        out = []
        while self._decode_buffer:
            if not self._skip_http_headers_if_present():
                break
            if len(self._decode_buffer) < 2:
                break

            second = self._decode_buffer[1]
            masked = bool(second & 0x80)
            length = second & 0x7F
            pos = 2
            if length == 126:
                if len(self._decode_buffer) < 4:
                    break
                length = (self._decode_buffer[2] << 8) | self._decode_buffer[3]
                pos = 4
            elif length == 127:
                self._decode_buffer.pop(0)
                continue
            if length > MAX_FRAME_SIZE:
                self._decode_buffer.pop(0)
                continue

            mask = b""
            if masked:
                if len(self._decode_buffer) < pos + 4:
                    break
                mask = bytes(self._decode_buffer[pos:pos + 4])
                pos += 4

            frame_len = pos + length
            if len(self._decode_buffer) < frame_len:
                break
            payload = bytes(self._decode_buffer[pos:frame_len])
            del self._decode_buffer[:frame_len]
            if masked:
                payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
            out.append(payload)

        return b"".join(out)

    def generate_client_code(self, language: str) -> Optional[str]:
        if language != "python":
            return None
        client_upgrade = CLIENT_UPGRADE.hex()
        return (
            "import os\n"
            "_xf_buf=bytearray()\n"
            "_xf_first=[True]\n"
            f"_xf_client_upgrade=bytes.fromhex('{client_upgrade}')\n"
            "def _xf_frame(c):\n"
            " if len(c)>65535: c=c[:65535]\n"
            " h=bytes([0x82])\n"
            " if len(c)<126: h+=bytes([0x80|len(c)])\n"
            " else: h+=bytes([0x80|126,(len(c)>>8)&0xFF,len(c)&0xFF])\n"
            " m=os.urandom(4)\n"
            " return h+m+bytes(b^m[i%4] for i,b in enumerate(c))\n"
            "def _xf_encode(d):\n"
            " if not d: return d\n"
            " out=[]\n"
            " if _xf_first[0]: out.append(_xf_client_upgrade); _xf_first[0]=False\n"
            " i=0\n"
            " while i<len(d): c=d[i:i+65535]; i+=65535; out.append(_xf_frame(c))\n"
            " return b''.join(out)\n"
            "def _xf_decode(d):\n"
            " _xf_buf.extend(d)\n"
            " out=[]\n"
            " while _xf_buf:\n"
            "  if _xf_buf.startswith((b'HTTP/',b'GET ',b'POST ')):\n"
            "   e=_xf_buf.find(b'\\r\\n\\r\\n')\n"
            "   if e==-1: break\n"
            "   del _xf_buf[:e+4]\n"
            "  if len(_xf_buf)<2: break\n"
            "  masked=bool(_xf_buf[1]&0x80); ln=_xf_buf[1]&0x7F; pos=2\n"
            "  if ln==126:\n"
            "   if len(_xf_buf)<4: break\n"
            "   ln=(_xf_buf[2]<<8)|_xf_buf[3]; pos=4\n"
            "  elif ln==127: _xf_buf.pop(0); continue\n"
            "  if ln>65535: _xf_buf.pop(0); continue\n"
            "  mask=b''\n"
            "  if masked:\n"
            "   if len(_xf_buf)<pos+4: break\n"
            "   mask=bytes(_xf_buf[pos:pos+4]); pos+=4\n"
            "  end=pos+ln\n"
            "  if len(_xf_buf)<end: break\n"
            "  p=bytes(_xf_buf[pos:end]); del _xf_buf[:end]\n"
            "  if masked: p=bytes(b^mask[i%4] for i,b in enumerate(p))\n"
            "  out.append(p)\n"
            " return b''.join(out)\n"
        )
