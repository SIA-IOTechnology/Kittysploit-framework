#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Little-endian uint32 header fields prepended to a binary message body."""

from __future__ import annotations

import socket
import ssl
import struct
from typing import Sequence


def pack_le32_header(*fields: int) -> bytes:
    return b"".join(struct.pack("<I", int(v) & 0xFFFFFFFF) for v in fields)


def build_le32_message(header_fields: Sequence[int], body: bytes) -> bytes:
    return pack_le32_header(*header_fields) + body


def send_tls_le32_message(
    host: str,
    port: int,
    message: bytes,
    timeout: float = 5.0,
    *,
    recv_size: int = 1024,
) -> bytes:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout) as raw:
        with context.wrap_socket(raw, server_hostname=host) as sock:
            sock.sendall(message)
            if recv_size <= 0:
                return b""
            try:
                sock.settimeout(timeout)
                return sock.recv(recv_size)
            except OSError:
                return b""
