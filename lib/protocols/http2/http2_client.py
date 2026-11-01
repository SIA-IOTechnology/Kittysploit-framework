#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HTTP/2 client mixin for modules (TLS ALPN h2 or prior-knowledge plaintext)."""

from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Iterator

from core.framework.base_module import BaseModule
from core.framework.option import OptBool, OptFloat

from lib.protocols.http2.connection import (
    http2_connection as _http2_connection,
    open_http2_socket as _open_http2_socket,
    probe_http2 as _probe_http2,
)
from lib.protocols.http2.grpc_request import Http2GrpcPostBuilder


class Http2_client(BaseModule):
    """Mixin: probe and send raw HTTP/2 request bytes over TCP/TLS."""

    h2_plaintext = OptBool(
        False,
        "Plaintext HTTP/2 prior knowledge (default: TLS + ALPN h2)",
        required=False,
        advanced=True,
    )
    h2_timeout = OptFloat(5.0, "HTTP/2 socket timeout (seconds)", required=False, advanced=True)
    h2_post_send_delay = OptFloat(
        1.0,
        "Seconds to wait after sending an HTTP/2 request",
        required=False,
        advanced=True,
    )

    def _h2_timeout(self) -> float:
        raw = getattr(self, "h2_timeout", None) or getattr(self, "grpc_timeout", None)
        if hasattr(raw, "value"):
            raw = raw.value
        return float(raw or 5.0)

    def _h2_plaintext(self) -> bool:
        raw = getattr(self, "h2_plaintext", None) or getattr(self, "plaintext", None)
        if hasattr(raw, "value"):
            raw = raw.value
        return bool(raw)

    def _h2_send_delay(self) -> float:
        raw = getattr(self, "h2_post_send_delay", None) or getattr(self, "post_send_delay", None)
        if hasattr(raw, "value"):
            raw = raw.value
        return float(raw or 1.0)

    def open_http2_socket(self, host: str, port: int):
        return _open_http2_socket(
            host,
            int(port),
            self._h2_timeout(),
            plaintext=self._h2_plaintext(),
        )

    def probe_http2(self, host: str, port: int) -> tuple[bool, str]:
        return _probe_http2(
            host,
            int(port),
            self._h2_timeout(),
            plaintext=self._h2_plaintext(),
        )

    @contextmanager
    def http2_connection(self, host: str, port: int) -> Iterator:
        with _http2_connection(
            host,
            int(port),
            self._h2_timeout(),
            plaintext=self._h2_plaintext(),
        ) as sock:
            yield sock

    def http2_grpc_post_builder(self, authority: str, grpc_path: str) -> Http2GrpcPostBuilder:
        use_tls = not self._h2_plaintext()
        return Http2GrpcPostBuilder(authority, grpc_path, use_tls=use_tls)

    def send_http2_request(self, host: str, port: int, request: bytes) -> None:
        with self.http2_connection(host, port) as sock:
            sock.sendall(request)
            delay = self._h2_send_delay()
            if delay > 0:
                time.sleep(delay)
