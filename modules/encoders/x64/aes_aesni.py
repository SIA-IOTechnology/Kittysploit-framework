#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""AES-128 (AES-NI) encoder for x64 shellcode — same layout as Awesome-EDR 02 style runners."""

from kittysploit import *

from core.lib.shellcode_aes import encode_shellcode_aes128_x64


class Module(Encoder):

    __info__ = {
        "name": "x64 AES-128 AES-NI Encoder",
        "description": (
            "Encrypts shellcode with AES-128-ECB and prepends an x64 AES-NI decoder stub "
            "(requires AES-NI on the target CPU)."
        ),
        "author": "KittySploit Team",
        "arch": Arch.X64,
        "platform": [Platform.WINDOWS, Platform.LINUX],
        "references": [
            "https://github.com/JoasASantos/Awesome-EDR-Evasion/tree/main/Codes",
        ],
    }

    def encode(self, payload):
        if not payload:
            return payload
        package = encode_shellcode_aes128_x64(payload)
        return package.assemble()
