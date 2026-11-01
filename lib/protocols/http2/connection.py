#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TCP/TLS connections with HTTP/2 ALPN or prior-knowledge plaintext."""

from __future__ import annotations

import socket
import ssl
from contextlib import contextmanager
from typing import Iterator


def open_http2_socket(
    host: str,
    port: int,
    timeout: float,
    *,
    plaintext: bool = False,
) -> socket.socket:
    sock = socket.create_connection((host, port), timeout)
    if plaintext:
        return sock
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(["h2"])
    wrapped = context.wrap_socket(sock, server_hostname=host)
    if wrapped.selected_alpn_protocol() != "h2":
        wrapped.close()
        raise RuntimeError("Peer did not negotiate ALPN h2")
    return wrapped


def probe_http2(
    host: str,
    port: int,
    timeout: float,
    *,
    plaintext: bool = False,
) -> tuple[bool, str]:
    try:
        with open_http2_socket(host, port, timeout, plaintext=plaintext):
            pass
        return True, "HTTP/2 reachable"
    except OSError as exc:
        return False, str(exc)
    except RuntimeError as exc:
        return False, str(exc)


@contextmanager
def http2_connection(
    host: str,
    port: int,
    timeout: float,
    *,
    plaintext: bool = False,
) -> Iterator[socket.socket]:
    sock = open_http2_socket(host, port, timeout, plaintext=plaintext)
    try:
        yield sock
    finally:
        sock.close()
