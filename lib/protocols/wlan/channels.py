#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""802.11 channel sets and scan hop ordering."""

from __future__ import annotations

_PRIORITY_2G = (1, 6, 11)

CHANNELS_2G = list(range(1, 15))
CHANNELS_5G_COMMON = [
    36, 40, 44, 48, 52, 56, 60, 64,
    100, 104, 108, 112, 116, 120, 124, 128,
    132, 136, 140, 144, 149, 153, 157, 161, 165,
]


def scan_hop_order(channels: list[int]) -> list[int]:
    priority = [c for c in _PRIORITY_2G if c in channels]
    rest_2g = [c for c in channels if c <= 14 and c not in _PRIORITY_2G]
    band_5g = [c for c in channels if c > 14]
    return priority + rest_2g + band_5g


def default_channels(band_5g: bool = True) -> list[int]:
    ch = list(CHANNELS_2G)
    if band_5g:
        ch.extend(CHANNELS_5G_COMMON)
    return scan_hop_order(ch)


def channel_to_freq_mhz(channel: int) -> int:
    if 1 <= channel <= 14:
        return 2407 + channel * 5 if channel != 14 else 2484
    if channel in range(36, 177):
        return 5000 + channel * 5
    return 0