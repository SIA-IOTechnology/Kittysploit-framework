#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Minimal HPACK encoding (literal strings, no Huffman) for raw HTTP/2 clients."""

from __future__ import annotations


def hpack_int(value: int, prefix: int, first: int = 0) -> bytes:
    limit = (1 << prefix) - 1
    if value < limit:
        return bytes([first | value])
    encoded = bytearray([first | limit])
    value -= limit
    while value >= 128:
        encoded.append((value & 0x7F) | 0x80)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def hpack_string(value: bytes) -> bytes:
    return hpack_int(len(value), 7) + value


def hpack_header(name: bytes, value: bytes, index: int = 0) -> bytes:
    encoded = bytearray(hpack_int(index, 4))
    if index == 0:
        encoded += hpack_string(name)
    encoded += hpack_string(value)
    return bytes(encoded)
