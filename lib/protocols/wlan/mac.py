#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""802.11 MAC address helpers and frame header construction."""

from __future__ import annotations

import os

from core.framework.base_module import BaseModule

BROADCAST_MAC = b"\xff" * 6


def str_to_mac(value: str | bytes) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    text = str(value or "").strip().lower().replace("-", ":")
    if not text:
        return b"\x00" * 6
    return bytes(int(octet, 16) for octet in text.split(":"))


def mac_to_str(mac: bytes) -> str:
    if len(mac) != 6:
        return "00:00:00:00:00:00"
    return ":".join(f"{b:02x}" for b in mac)


def is_group_mac(mac: str | bytes) -> bool:
    raw = mac if isinstance(mac, bytes) else str_to_mac(str(mac))
    return bool(raw[0] & 0x01)


def mac_header(
    fc: bytes,
    addr1: bytes,
    addr2: bytes,
    addr3: bytes,
    duration: bytes = b"\x00\x00",
) -> bytes:
    """24-byte 802.11 MAC header (sequence control zeroed)."""
    return fc + duration + addr1 + addr2 + addr3 + b"\x00\x00"


def random_client_mac() -> bytes:
    return bytes([0x02]) + os.urandom(5)


class Wlan_mac(BaseModule):
    """Optional mixin with MAC helpers (usually covered by :class:`Wlan_dot11`)."""

    @staticmethod
    def wlan_str_to_mac(value: str | bytes) -> bytes:
        return str_to_mac(value)

    @staticmethod
    def wlan_mac_to_str(mac: bytes) -> str:
        return mac_to_str(mac)

    @staticmethod
    def wlan_is_group_mac(mac: str | bytes) -> bool:
        return is_group_mac(mac)

    @staticmethod
    def wlan_mac_header(
        fc: bytes,
        addr1: bytes,
        addr2: bytes,
        addr3: bytes,
        duration: bytes = b"\x00\x00",
    ) -> bytes:
        return mac_header(fc, addr1, addr2, addr3, duration=duration)

    @staticmethod
    def wlan_random_client_mac() -> bytes:
        return random_client_mac()

    @staticmethod
    def wlan_broadcast_mac() -> bytes:
        return BROADCAST_MAC