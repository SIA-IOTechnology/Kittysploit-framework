#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gRPC length-prefixed messages and minimal protobuf helpers."""

from __future__ import annotations


def protobuf_varint(value: int) -> bytes:
    encoded = bytearray()
    while value > 0x7F:
        encoded.append((value & 0x7F) | 0x80)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def protobuf_length_delimited(field_number: int, payload: bytes) -> bytes:
    tag = (field_number << 3) | 2
    return protobuf_varint(tag) + protobuf_varint(len(payload)) + payload


def grpc_message_frame(message: bytes, *, compressed: bool = False) -> bytes:
    prefix = b"\x01" if compressed else b"\x00"
    return prefix + len(message).to_bytes(4, "big") + message
