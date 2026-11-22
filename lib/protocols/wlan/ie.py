#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""802.11 information element walking and common IE tags."""

from __future__ import annotations

from collections.abc import Iterator

SSID_IE = 0
RATES_IE = 1
DS_PARAM_IE = 3
RSN_IE = 48
VENDOR_IE = 221
EXTENSION_IE = 255
MDIE_IE = 54
EXT_OWE_TRANSITION = 32

WPA_OUI = bytes.fromhex("0050f2")
RSN_OUI = bytes.fromhex("000fac")

SUPPORTED_RATES = bytes([0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24])
EXT_SUPPORTED_RATES = bytes([0x30, 0x48, 0x60, 0x6C])

# WPA2-PSK + CCMP (client assoc fallback)
GENERIC_RSN_PSK_IE = bytes.fromhex(
    "30140100000fac040100000fac040100000fac020000"
)


def iter_extension_elements(data: bytes, start: int = 0) -> Iterator[tuple[int, bytes, bytes]]:
    i, n = start, len(data)
    while i + 2 <= n:
        tag_id = data[i]
        length = data[i + 1]
        end = i + 2 + length
        if end > n:
            break
        if tag_id == EXTENSION_IE and length >= 1:
            ext_id = data[i + 2]
            body = data[i + 3 : end]
            yield ext_id, body, data[i:end]
        i = end


def iter_information_elements(data: bytes, start: int = 0) -> Iterator[tuple[int, bytes, bytes]]:
    i, n = start, len(data)
    while i + 2 <= n:
        tag_id = data[i]
        length = data[i + 1]
        end = i + 2 + length
        if end > n:
            break
        yield tag_id, data[i + 2 : end], data[i : end]
        i = end


def parse_ssid(ies: bytes) -> str:
    for tag, body, _ in iter_information_elements(ies):
        if tag == SSID_IE:
            return body.decode("utf-8", errors="replace")
    return ""


def parse_ds_channel(ies: bytes) -> int | None:
    for tag, body, _ in iter_information_elements(ies):
        if tag == DS_PARAM_IE and body:
            return body[0]
    return None


def find_rsn_ie(ies: bytes) -> bytes:
    for tag, body, raw in iter_information_elements(ies):
        if tag == RSN_IE:
            return raw
    return b""


def ssid_ie(ssid: str) -> bytes:
    enc = ssid.encode("utf-8", errors="ignore")[:32]
    return bytes([SSID_IE, len(enc)]) + enc


def supported_rates_ie() -> bytes:
    return bytes([RATES_IE, len(SUPPORTED_RATES)]) + SUPPORTED_RATES


def ext_supported_rates_ie() -> bytes:
    return bytes([0x32, len(EXT_SUPPORTED_RATES)]) + EXT_SUPPORTED_RATES


def ds_param_ie(channel: int) -> bytes:
    ch = int(channel) & 0xFF
    return bytes([DS_PARAM_IE, 1, ch])


def tim_ie() -> bytes:
    body = bytes([0, 1, 0, 0, 0, 0, 0, 0])
    return bytes([5, len(body)]) + body