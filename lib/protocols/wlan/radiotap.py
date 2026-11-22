#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Strip Linux/macOS Radiotap or AVS headers from monitor-mode captures."""

from __future__ import annotations


def strip_monitor_header(frame: bytes) -> bytes:
    if len(frame) < 4:
        return frame
    # Radiotap: version 0, pad 0, little-endian length at 2-3
    if frame[0] == 0 and frame[1] == 0:
        length = frame[2] | (frame[3] << 8)
        if 8 <= length <= len(frame):
            return frame[length:]
    # AVS/Prism (some drivers): length in bytes 2-3 big-endian when magic 0x40 0x00
    if frame[0] == 0x40 and frame[1] == 0x00 and len(frame) >= 4:
        length = (frame[2] << 8) | frame[3]
        if 8 <= length <= len(frame):
            return frame[length:]
    return frame