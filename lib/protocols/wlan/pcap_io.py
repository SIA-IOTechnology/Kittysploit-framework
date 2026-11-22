#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Minimal PCAP / PCAPNG reader and writer (stdlib only)."""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Iterator


PCAP_MAGIC = 0xA1B2C3D4
PCAP_MAGIC_LE = 0xD4C3B2A1


def iter_pcap_packets(path: str | Path) -> Iterator[bytes]:
    data = Path(path).read_bytes()
    if len(data) < 24:
        return
    magic, = struct.unpack_from("<I", data, 0)
    le = magic in (PCAP_MAGIC_LE, 0x4D3C2B1A)
    endian = "<" if le else ">"
    if magic not in (PCAP_MAGIC, PCAP_MAGIC_LE, 0x1A2B3C4D, 0x4D3C2B1A):
        # PCAPNG: scan for Enhanced Packet Blocks (type 0x00000006)
        yield from _iter_pcapng(data)
        return
    offset = 24
    while offset + 16 <= len(data):
        _ts_sec, _ts_usec, incl_len, _orig_len = struct.unpack_from(endian + "IIII", data, offset)
        offset += 16
        if offset + incl_len > len(data):
            break
        yield data[offset : offset + incl_len]
        offset += incl_len


def _iter_pcapng(data: bytes) -> Iterator[bytes]:
    offset = 0
    while offset + 12 <= len(data):
        block_type, block_len = struct.unpack_from("<II", data, offset)
        if block_len < 12 or offset + block_len > len(data):
            break
        if block_type == 0x00000006:
            pkt_start = offset + 20
            pkt_end = offset + block_len - 4
            if pkt_end > pkt_start:
                yield data[pkt_start:pkt_end]
        offset += block_len


def write_pcap(path: str | Path, packets: list[bytes]) -> Path:
    out = Path(path)
    header = struct.pack("<IHHiIII", PCAP_MAGIC_LE, 2, 4, 0, 0, 65535, 105)
    body = bytearray(header)
    for pkt in packets:
        ts = 0
        body += struct.pack("<IIII", ts, 0, len(pkt), len(pkt))
        body += pkt
    out.write_bytes(body)
    return out