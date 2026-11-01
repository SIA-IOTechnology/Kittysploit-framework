#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gRPC framing and minimal protobuf helpers as a module mixin."""

from __future__ import annotations

from core.framework.base_module import BaseModule

from lib.protocols.grpc.framing import (
    grpc_message_frame as _grpc_message_frame,
    protobuf_length_delimited as _protobuf_length_delimited,
    protobuf_varint as _protobuf_varint,
)


class Grpc_client(BaseModule):
    """Mixin: length-delimited protobuf fields and gRPC message envelopes."""

    def protobuf_varint(self, value: int) -> bytes:
        return _protobuf_varint(value)

    def protobuf_length_delimited(self, field_number: int, payload: bytes) -> bytes:
        return _protobuf_length_delimited(field_number, payload)

    def grpc_message_frame(self, message: bytes, *, compressed: bool = False) -> bytes:
        return _grpc_message_frame(message, compressed=compressed)

    def grpc_field1_bytes_body(self, file_content: bytes) -> bytes:
        """Common SendQueryResult-style field 1 (length-delimited bytes)."""
        return self.protobuf_length_delimited(1, file_content)
