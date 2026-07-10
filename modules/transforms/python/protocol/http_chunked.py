#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
HTTP chunked mimic transform.

The first server-side encode prepends an HTTP/1.1 response header, the first
client-side encode generated for payloads prepends an HTTP POST request header,
then both directions use Transfer-Encoding: chunked style frames.
"""

from typing import Optional
from kittysploit import *


MAX_CHUNK_SIZE = 16384
MAX_BUFFER_SIZE = 1024 * 1024
CRLF = b"\r\n"
HEADER_END = b"\r\n\r\n"

SERVER_HEADER = (
    b"HTTP/1.1 200 OK\r\n"
    b"Server: nginx\r\n"
    b"Content-Type: application/octet-stream\r\n"
    b"Transfer-Encoding: chunked\r\n"
    b"Connection: keep-alive\r\n"
    b"\r\n"
)

CLIENT_HEADER = (
    b"POST /api/events HTTP/1.1\r\n"
    b"Host: update.local\r\n"
    b"User-Agent: Mozilla/5.0\r\n"
    b"Content-Type: application/octet-stream\r\n"
    b"Transfer-Encoding: chunked\r\n"
    b"Connection: keep-alive\r\n"
    b"\r\n"
)


class Module(Transform):
    """HTTP chunked transfer mimic transform."""

    SUPPORTED_CLIENT_LANGUAGES = ["python"]

    __info__ = {
        "name": "HTTP Chunked Mimic Transform",
        "description": "Wraps C2 bytes in HTTP/1.1 chunked transfer frames with initial HTTP-like headers.",
        "author": "KittySploit Team",
        "version": "1.0.0",
    }

    def __init__(self, framework=None):
        super().__init__(framework)
        self._decode_buffer = bytearray()
        self._first_encode_done = False

    def _encode_chunks(self, data: bytes) -> bytes:
        out = []
        remaining = data
        while remaining:
            chunk = remaining[:MAX_CHUNK_SIZE]
            remaining = remaining[MAX_CHUNK_SIZE:]
            out.append(("%x" % len(chunk)).encode("ascii") + CRLF + chunk + CRLF)
        return b"".join(out)

    def encode(self, data: bytes, offset: int = 0) -> bytes:
        if not data:
            return data
        out = []
        if not self._first_encode_done:
            out.append(SERVER_HEADER)
            self._first_encode_done = True
        out.append(self._encode_chunks(data))
        return b"".join(out)

    def _skip_http_headers_if_present(self) -> bool:
        markers = (b"HTTP/", b"POST ", b"GET ", b"PUT ", b"PATCH ")
        if not any(self._decode_buffer.startswith(marker) for marker in markers):
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

            line_end = self._decode_buffer.find(CRLF)
            if line_end == -1:
                break
            size_line = bytes(self._decode_buffer[:line_end]).split(b";", 1)[0].strip()
            try:
                chunk_len = int(size_line, 16)
            except ValueError:
                self._decode_buffer.pop(0)
                continue
            if chunk_len < 0 or chunk_len > MAX_CHUNK_SIZE:
                self._decode_buffer.pop(0)
                continue

            frame_len = line_end + len(CRLF) + chunk_len + len(CRLF)
            if len(self._decode_buffer) < frame_len:
                break
            payload_start = line_end + len(CRLF)
            payload_end = payload_start + chunk_len
            out.append(bytes(self._decode_buffer[payload_start:payload_end]))
            del self._decode_buffer[:frame_len]

        return b"".join(out)

    def generate_client_code(self, language: str) -> Optional[str]:
        if language != "python":
            return None
        client_header = CLIENT_HEADER.hex()
        return (
            "_xf_buf=bytearray()\n"
            "_xf_first=[True]\n"
            f"_xf_client_header=bytes.fromhex('{client_header}')\n"
            "def _xf_encode(d):\n"
            " if not d: return d\n"
            " out=[]\n"
            " if _xf_first[0]: out.append(_xf_client_header); _xf_first[0]=False\n"
            " i=0\n"
            " while i<len(d):\n"
            "  c=d[i:i+16384]; i+=16384\n"
            "  out.append(('%x'%len(c)).encode()+b'\\r\\n'+c+b'\\r\\n')\n"
            " return b''.join(out)\n"
            "def _xf_decode(d):\n"
            " _xf_buf.extend(d)\n"
            " out=[]\n"
            " while _xf_buf:\n"
            "  if _xf_buf.startswith((b'HTTP/',b'POST ',b'GET ',b'PUT ',b'PATCH ')):\n"
            "   e=_xf_buf.find(b'\\r\\n\\r\\n')\n"
            "   if e==-1: break\n"
            "   del _xf_buf[:e+4]\n"
            "  i=_xf_buf.find(b'\\r\\n')\n"
            "  if i==-1: break\n"
            "  try: ln=int(bytes(_xf_buf[:i]).split(b';',1)[0].strip(),16)\n"
            "  except Exception: _xf_buf.pop(0); continue\n"
            "  if ln>16384: _xf_buf.pop(0); continue\n"
            "  end=i+2+ln+2\n"
            "  if len(_xf_buf)<end: break\n"
            "  out.append(bytes(_xf_buf[i+2:i+2+ln])); del _xf_buf[:end]\n"
            " return b''.join(out)\n"
        )
