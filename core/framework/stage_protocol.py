#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Stage delivery protocol v2 (length + hash + ACK, safe partial reads)."""

from __future__ import annotations

import hashlib
import socket
import struct
from typing import Optional

STAGE_V1 = 1
STAGE_V2 = 2

STAGE_V2_MAGIC = b"KS02"
STAGE_V2_ACK = b"ACK\x01"
STAGE_V2_HEADER_SIZE = 44
STAGE_V2_MAX_SIZE = 16 * 1024 * 1024


class StageProtocolError(Exception):
    """Raised when stage framing or verification fails."""


def read_exact(sock: socket.socket, size: int) -> bytes:
    """Read exactly ``size`` bytes from a TCP socket."""
    if size <= 0:
        return b""
    chunks = bytearray()
    while len(chunks) < size:
        try:
            data = sock.recv(size - len(chunks))
        except socket.timeout as exc:
            raise StageProtocolError(
                f"timed out while reading staged payload ({len(chunks)}/{size} bytes)"
            ) from exc
        if not data:
            raise StageProtocolError(
                f"connection closed while reading staged payload ({len(chunks)}/{size} bytes)"
            )
        chunks.extend(data)
    return bytes(chunks)


def build_stage_v2_header(stage_bytes: bytes) -> bytes:
    stage = bytes(stage_bytes or b"")
    if len(stage) > STAGE_V2_MAX_SIZE:
        raise StageProtocolError(
            f"stage payload too large ({len(stage)} > {STAGE_V2_MAX_SIZE})"
        )
    digest = hashlib.sha256(stage).digest()
    return STAGE_V2_MAGIC + struct.pack(">HHI", STAGE_V2, 0, len(stage)) + digest


def parse_stage_v2_header(header: bytes) -> tuple[int, bytes]:
    if len(header) != STAGE_V2_HEADER_SIZE:
        raise StageProtocolError(f"invalid stage header size ({len(header)})")
    magic = header[:4]
    if magic != STAGE_V2_MAGIC:
        raise StageProtocolError(f"invalid stage magic: {magic!r}")
    version, _flags, length = struct.unpack(">HHI", header[4:12])
    if version != STAGE_V2:
        raise StageProtocolError(f"unsupported stage version: {version}")
    if length <= 0 or length > STAGE_V2_MAX_SIZE:
        raise StageProtocolError(f"invalid stage length: {length}")
    return length, header[12:44]


def send_stage_over_socket(
    sock: socket.socket,
    stage_bytes: bytes,
    *,
    protocol: int = STAGE_V2,
    ack_timeout: float = 5.0,
) -> None:
    """Send a stage using protocol v2 (default) or legacy v1."""
    stage = bytes(stage_bytes or b"")
    if protocol == STAGE_V1:
        header = struct.pack(">I", len(stage))
        sock.sendall(header + stage)
        return

    header = build_stage_v2_header(stage)
    sock.sendall(header)
    previous = sock.gettimeout()
    try:
        sock.settimeout(ack_timeout)
        ack = read_exact(sock, len(STAGE_V2_ACK))
    finally:
        sock.settimeout(previous)
    if ack != STAGE_V2_ACK:
        raise StageProtocolError(f"unexpected stage ACK: {ack!r}")
    sock.sendall(stage)


def recv_stage_from_socket(
    sock: socket.socket,
    *,
    protocol: Optional[int] = None,
    send_ack: bool = True,
) -> bytes:
    """Receive a stage frame from the server socket."""
    if protocol == STAGE_V1:
        header = read_exact(sock, 4)
        length = struct.unpack(">I", header)[0]
        if length <= 0 or length > STAGE_V2_MAX_SIZE:
            raise StageProtocolError(f"invalid legacy stage length: {length}")
        return read_exact(sock, length)

    header = read_exact(sock, STAGE_V2_HEADER_SIZE)
    length, expected_digest = parse_stage_v2_header(header)
    if send_ack:
        sock.sendall(STAGE_V2_ACK)
    body = read_exact(sock, length)
    digest = hashlib.sha256(body).digest()
    if digest != expected_digest:
        raise StageProtocolError("stage sha256 mismatch")
    return body
