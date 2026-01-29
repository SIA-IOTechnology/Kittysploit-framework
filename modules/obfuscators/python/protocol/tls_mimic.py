#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
TLS/HTTPS mimic obfuscator: wraps C2 traffic in TLS Application Data records
so the stream looks like HTTPS (TLS 1.2) on the wire while using plain TCP.
Each encode() wraps data in a TLS record (type=23, version=0x0303, length, payload).
Decode is stateful: buffers incoming bytes and parses records, returning payloads only.
Uses connection_copy() so each connection has its own decode buffer.
"""

from typing import Optional
from kittysploit import *

# TLS record: type (1) + version (2) + length (2) + fragment
TLS_HEADER_LEN = 5
TLS_APPLICATION_DATA = 0x17
TLS_VERSION_1_2 = (0x03, 0x03)
TLS_MAX_FRAGMENT = 16384  # 2^14


class Module(Obfuscator):
    """
    TLS/HTTPS mimic: wrap traffic in TLS Application Data records.
    Makes raw TCP look like HTTPS on the wire (TLS record structure only; payload is not encrypted).
    """

    SUPPORTED_CLIENT_LANGUAGES = ["python"]

    __info__ = {
        "name": "TLS/HTTPS Mimic Obfuscator",
        "description": "Wraps C2 stream in TLS 1.2 Application Data records so traffic looks like HTTPS on the wire (plain TCP).",
        "author": "KittySploit Team",
        "version": "1.0.0",
    }

    def __init__(self, framework=None):
        super().__init__(framework)
        self._decode_buffer = bytearray()

    def _encode_record(self, payload: bytes) -> bytes:
        """Build one TLS Application Data record: type=23, version=0x0303, length, payload."""
        if len(payload) > TLS_MAX_FRAGMENT:
            payload = payload[:TLS_MAX_FRAGMENT]
        length = len(payload)
        header = bytes([
            TLS_APPLICATION_DATA,
            TLS_VERSION_1_2[0],
            TLS_VERSION_1_2[1],
            (length >> 8) & 0xFF,
            length & 0xFF,
        ])
        return header + payload

    def encode(self, data: bytes, offset: int = 0) -> bytes:
        """Wrap data in one or more TLS Application Data records (chunked if > 16384 bytes)."""
        if not data:
            return data
        out = []
        remaining = data
        while remaining:
            chunk = remaining[:TLS_MAX_FRAGMENT]
            remaining = remaining[TLS_MAX_FRAGMENT:]
            out.append(self._encode_record(chunk))
        return b"".join(out)

    def decode(self, data: bytes, offset: int = 0) -> bytes:
        """Parse TLS records from buffered stream; return concatenated payloads. Stateful (uses _decode_buffer)."""
        if not data:
            return data
        self._decode_buffer.extend(data)
        out = []
        while len(self._decode_buffer) >= TLS_HEADER_LEN:
            # type, ver_hi, ver_lo, len_hi, len_lo
            frag_len = (self._decode_buffer[3] << 8) | self._decode_buffer[4]
            if frag_len > TLS_MAX_FRAGMENT:
                # Invalid length; drop first byte and resync
                self._decode_buffer.pop(0)
                continue
            if len(self._decode_buffer) < TLS_HEADER_LEN + frag_len:
                break
            payload = bytes(self._decode_buffer[TLS_HEADER_LEN : TLS_HEADER_LEN + frag_len])
            out.append(payload)
            del self._decode_buffer[: TLS_HEADER_LEN + frag_len]
        return b"".join(out)

    def generate_client_code(self, language: str) -> Optional[str]:
        """Generate Python code that wraps/parses TLS records on the client (same format)."""
        if language != "python":
            return None
        return (
            "_obf_buf=bytearray()\n"
            "def _obf_encode(d):\n"
            " if not d: return d\n"
            " out=[]\n"
            " i=0\n"
            " while i<len(d):\n"
            "  c=d[i:i+16384];i+=16384\n"
            "  h=bytes([0x17,0x03,0x03,(len(c)>>8)&0xFF,len(c)&0xFF])\n"
            "  out.append(h+c)\n"
            " return b''.join(out)\n"
            "def _obf_decode(d):\n"
            " _obf_buf.extend(d)\n"
            " out=[]\n"
            " while len(_obf_buf)>=5:\n"
            "  fl=(_obf_buf[3]<<8)|_obf_buf[4]\n"
            "  if fl>16384: _obf_buf.pop(0); continue\n"
            "  if len(_obf_buf)<5+fl: break\n"
            "  out.append(bytes(_obf_buf[5:5+fl])); del _obf_buf[:5+fl]\n"
            " return b''.join(out)\n"
        )
