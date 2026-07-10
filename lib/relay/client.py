#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Relay client helpers (operator + agent side)."""

from __future__ import annotations

import socket
from typing import Callable, Optional, Union

from lib.relay.crypto_stream import SecureRelayStream, wrap_secure_stream
from lib.relay.p2p_relay_core import (
    PROTOCOL_VERSION,
    PROTOCOL_VERSION_V2,
    ROLE_AGENT,
    ROLE_OPERATOR,
    perform_handshake,
)

SocketLike = Union[socket.socket, SecureRelayStream]


def connect_relay_peer(
    relay_host: str,
    relay_port: int,
    role: str,
    token: str,
    *,
    timeout: float = 120.0,
    encrypt: bool = True,
    psk: str = "",
    keepalive_interval: float = 30.0,
    keepalive_timeout: float = 90.0,
    protocol_version: str = PROTOCOL_VERSION_V2,
    on_disconnect: Optional[Callable[[], None]] = None,
) -> SocketLike:
    """Connect to KittyRelay, perform handshake, optionally wrap E2E encryption."""
    sock = socket.create_connection((relay_host, int(relay_port)), timeout=timeout)
    try:
        perform_handshake(sock, role, token, timeout=timeout, version=protocol_version)
    except Exception:
        sock.close()
        raise
    sock.settimeout(None)
    if encrypt:
        return wrap_secure_stream(
            sock,
            token,
            psk=psk,
            keepalive_interval=keepalive_interval,
            keepalive_timeout=keepalive_timeout,
            on_disconnect=on_disconnect,
        )
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except OSError:
        pass
    return sock


def connect_operator(
    relay_host: str,
    relay_port: int,
    token: str,
    timeout: float = 120.0,
    *,
    encrypt: bool = True,
    psk: str = "",
    keepalive_interval: float = 30.0,
    keepalive_timeout: float = 90.0,
    on_disconnect: Optional[Callable[[], None]] = None,
) -> SocketLike:
    return connect_relay_peer(
        relay_host,
        relay_port,
        ROLE_OPERATOR,
        token,
        timeout=timeout,
        encrypt=encrypt,
        psk=psk,
        keepalive_interval=keepalive_interval,
        keepalive_timeout=keepalive_timeout,
        on_disconnect=on_disconnect,
    )


def connect_agent(
    relay_host: str,
    relay_port: int,
    token: str,
    timeout: float = 30.0,
    *,
    encrypt: bool = True,
    psk: str = "",
    keepalive_interval: float = 30.0,
    keepalive_timeout: float = 90.0,
) -> SocketLike:
    return connect_relay_peer(
        relay_host,
        relay_port,
        ROLE_AGENT,
        token,
        timeout=timeout,
        encrypt=encrypt,
        psk=psk,
        keepalive_interval=keepalive_interval,
        keepalive_timeout=keepalive_timeout,
    )
