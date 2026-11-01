#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""LE32-prefixed binary messages over TLS (Phoenix Monitor and similar)."""

from __future__ import annotations

from typing import Sequence

from core.framework.base_module import BaseModule
from core.framework.option import OptFloat

from lib.protocols.binary.le32_frame import (
    build_le32_message as _build_le32_message,
    pack_le32_header as _pack_le32_header,
    send_tls_le32_message as _send_tls_le32_message,
)


class Le32_tls_client(BaseModule):
    """Mixin: pack little-endian uint32 headers and send over TLS."""

    le32_timeout = OptFloat(5.0, "TLS LE32 socket timeout (seconds)", required=False, advanced=True)

    def _le32_timeout(self) -> float:
        raw = getattr(self, "le32_timeout", None) or getattr(self, "monitor_timeout", None)
        if hasattr(raw, "value"):
            raw = raw.value
        return float(raw or 5.0)

    def pack_le32_header(self, *fields: int) -> bytes:
        return _pack_le32_header(*fields)

    def build_le32_message(self, header_fields: Sequence[int], body: bytes) -> bytes:
        return _build_le32_message(header_fields, body)

    def send_tls_le32_message(
        self,
        host: str,
        port: int,
        message: bytes,
        *,
        recv_size: int = 1024,
    ) -> bytes:
        return _send_tls_le32_message(
            host,
            int(port),
            message,
            timeout=self._le32_timeout(),
            recv_size=recv_size,
        )
