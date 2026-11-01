#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build a single-stream HTTP/2 POST request carrying one gRPC message."""

from __future__ import annotations

from lib.protocols.grpc.framing import grpc_message_frame
from lib.protocols.http2 import frames as h2
from lib.protocols.http2.hpack import hpack_header


class Http2GrpcPostBuilder:
    """One-shot HTTP/2 client request: SETTINGS + HEADERS + DATA (END_STREAM)."""

    def __init__(self, authority: str, grpc_path: str, *, use_tls: bool = True) -> None:
        self._authority = authority.encode() if isinstance(authority, str) else authority
        self._path = grpc_path.encode() if isinstance(grpc_path, str) else grpc_path
        self._use_tls = use_tls
        self._extra: list[tuple[bytes, bytes]] = []

    def header(self, name: bytes | str, value: bytes | str) -> "Http2GrpcPostBuilder":
        nb = name.encode() if isinstance(name, str) else name
        vb = value.encode() if isinstance(value, str) else value
        self._extra.append((nb, vb))
        return self

    def _encode_headers(self) -> bytes:
        block = bytearray()
        block += b"\x83"  # :method POST (static table)
        block += b"\x87" if self._use_tls else b"\x86"  # :scheme
        block += hpack_header(b":path", self._path, 4)
        block += hpack_header(b":authority", self._authority, 1)
        block += hpack_header(b"content-type", b"application/grpc", 31)
        block += hpack_header(b"te", b"trailers")
        for name, value in self._extra:
            block += hpack_header(name, value)
        return bytes(block)

    def build(self, grpc_body: bytes, stream_id: int = 1) -> bytes:
        headers = self._encode_headers()
        data = grpc_message_frame(grpc_body)
        return (
            h2.CLIENT_PREFACE
            + h2.h2_frame(h2.FRAME_SETTINGS, 0, 0)
            + h2.h2_frame(h2.FRAME_HEADERS, h2.FLAG_END_HEADERS, stream_id, headers)
            + h2.h2_frame(h2.FRAME_DATA, h2.FLAG_END_STREAM, stream_id, data)
        )
