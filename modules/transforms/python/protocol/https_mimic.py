#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Optional
from kittysploit import *

# TLS record: type (1) + version (2) + length (2) + fragment
TLS_HEADER_LEN = 5
TLS_HANDSHAKE = 0x16
TLS_APPLICATION_DATA = 0x17
TLS_VERSION_1_2 = (0x03, 0x03)
TLS_MAX_FRAGMENT = 16384  # 2^14

# Minimal TLS 1.2 Client Hello (RFC 5246): record 0x16 0x03 0x03 + handshake 0x01 (Client Hello)
# Body: version 0x0303, random 32 bytes, session_id_len 0, 1 cipher suite, null compression, no extensions
_CLIENT_HELLO_RANDOM = bytes([0x41] * 32)  # fixed for reproducibility
CLIENT_HELLO_BYTES = (
    b"\x16\x03\x03\x00\x2f"  # record: handshake, TLS 1.2, length 47
    b"\x01\x00\x00\x2b\x03\x03"  # Client Hello, len 43, version 1.2
    + _CLIENT_HELLO_RANDOM
    + b"\x00"  # session_id_len
    + b"\x00\x02\xc0\x2f"  # cipher_suites_len 2, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    + b"\x01\x00"  # compressions_len 1, null
    + b"\x00\x00"  # extensions_len 0
)

# Minimal TLS 1.2 Server Hello: record + handshake 0x02 (Server Hello)
# Body: version 0x0303, random 32, session_id_len 0, same cipher, compression 0
_SERVER_HELLO_RANDOM = bytes([0x42] * 32)
SERVER_HELLO_BYTES = (
    b"\x16\x03\x03\x00\x2a"  # record: handshake, TLS 1.2, length 42
    b"\x02\x00\x00\x26\x03\x03"  # Server Hello, len 38, version 1.2
    + _SERVER_HELLO_RANDOM
    + b"\x00"  # session_id_len
    + b"\xc0\x2f"  # cipher_suite
    + b"\x00"  # compression null
)


class Module(Obfuscator):
    """
    HTTPS mimic: fake TLS handshake (Client Hello / Server Hello) then Application Data.
    Wireshark will show the flow as HTTPS (handshake + TLS Application Data).
    """

    SUPPORTED_CLIENT_LANGUAGES = ["python"]

    __info__ = {
        "name": "HTTPS Mimic Obfuscator",
        "description": "Sends fake TLS 1.2 Client/Server Hello at start, then TLS Application Data.",
        "author": "KittySploit Team",
        "version": "1.0.0",
    }

    def __init__(self, framework=None):
        super().__init__(framework)
        self._decode_buffer = bytearray()
        self._first_encode_done = False

    def _encode_app_record(self, payload: bytes) -> bytes:
        """Build one TLS Application Data record."""
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
        """First call: prepend Server Hello then Application Data. Next calls: Application Data only."""
        if not data:
            return data
        out = []
        if not self._first_encode_done:
            out.append(SERVER_HELLO_BYTES)
            self._first_encode_done = True
        remaining = data
        while remaining:
            chunk = remaining[:TLS_MAX_FRAGMENT]
            remaining = remaining[TLS_MAX_FRAGMENT:]
            out.append(self._encode_app_record(chunk))
        return b"".join(out)

    def decode(self, data: bytes, offset: int = 0) -> bytes:
        """Parse TLS records; skip handshake (type 22), return only Application Data (type 23) payloads."""
        if not data:
            return data
        self._decode_buffer.extend(data)
        out = []
        while len(self._decode_buffer) >= TLS_HEADER_LEN:
            rec_type = self._decode_buffer[0]
            frag_len = (self._decode_buffer[3] << 8) | self._decode_buffer[4]
            if frag_len > TLS_MAX_FRAGMENT:
                self._decode_buffer.pop(0)
                continue
            if len(self._decode_buffer) < TLS_HEADER_LEN + frag_len:
                break
            fragment = bytes(self._decode_buffer[TLS_HEADER_LEN : TLS_HEADER_LEN + frag_len])
            del self._decode_buffer[: TLS_HEADER_LEN + frag_len]
            if rec_type == TLS_APPLICATION_DATA:
                out.append(fragment)
            # type 22 (handshake): discard
        return b"".join(out)

    def generate_client_code(self, language: str) -> Optional[str]:
        """Generate Python: send Client Hello once after connect, then _obf_encode/_obf_decode (skip handshake in decode)."""
        if language != "python":
            return None
        # Client Hello as bytes literal (escape for Python)
        ch_hex = CLIENT_HELLO_BYTES.hex()
        ch_repr = "bytes.fromhex('" + ch_hex + "')"
        return (
            "_obf_buf=bytearray()\n"
            "_obf_client_hello=" + ch_repr + "\n"
            "def _obf_send_client_hello(sock):\n"
            " sock.sendall(_obf_client_hello)\n"
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
            "  rt=_obf_buf[0];fl=(_obf_buf[3]<<8)|_obf_buf[4]\n"
            "  if fl>16384: _obf_buf.pop(0); continue\n"
            "  if len(_obf_buf)<5+fl: break\n"
            "  frag=bytes(_obf_buf[5:5+fl]); del _obf_buf[:5+fl]\n"
            "  if rt==0x17: out.append(frag)\n"
            " return b''.join(out)\n"
        )