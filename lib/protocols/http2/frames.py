#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HTTP/2 frame encoding for prior-knowledge clients."""

from __future__ import annotations

import struct

CLIENT_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

FRAME_SETTINGS = 4
FRAME_HEADERS = 1
FRAME_DATA = 0

FLAG_END_HEADERS = 0x04
FLAG_END_STREAM = 0x01


def h2_frame(frame_type: int, flags: int, stream_id: int, payload: bytes = b"") -> bytes:
    return (
        len(payload).to_bytes(3, "big")
        + bytes([frame_type, flags])
        + struct.pack("!I", stream_id & 0x7FFFFFFF)
        + payload
    )
