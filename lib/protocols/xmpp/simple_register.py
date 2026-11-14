#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Minimal XMPP in-band registration (XEP-0077) over TCP."""

from __future__ import annotations

import re
import socket
from typing import Optional


class XmppRegisterError(RuntimeError):
    pass


def _recv_until(sock: socket.socket, needle: bytes, limit: int = 16384) -> bytes:
    buf = b""
    sock.settimeout(15)
    while needle not in buf and len(buf) < limit:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
    return buf


def xmpp_register(
    host: str,
    port: int,
    username: str,
    password: str,
    *,
    domain: Optional[str] = None,
    timeout: float = 20,
) -> str:
    """
    Register ``username`` on ``host:port``. Returns the negotiated XMPP domain.
    Raises XmppRegisterError on failure.
    """
    user = (username or "").strip()
    pwd = password or ""
    if not user or not pwd:
        raise XmppRegisterError("username and password required")

    domain_hint = (domain or host or "").strip()
    sock = socket.create_connection((host, int(port)), timeout=timeout)
    try:
        sock.sendall(
            (
                "<?xml version='1.0'?>"
                f"<stream:stream xmlns='jabber:client' "
                f"xmlns:stream='http://etherx.jabber.org/streams' "
                f"version='1.0' to='{domain_hint}'>"
            ).encode()
        )
        opening = _recv_until(sock, b">")
        match = re.search(rb'from=["\']([^"\']+)', opening)
        xmpp_domain = match.group(1).decode(errors="replace") if match else domain_hint

        features = _recv_until(sock, b"</stream:features>")
        if b"<register" not in features and b"register" not in features:
            raise XmppRegisterError("in-band registration not advertised")

        iq = (
            f"<iq type='set' id='ks-reg1'>"
            f"<query xmlns='jabber:iq:register'>"
            f"<username>{user}</username>"
            f"<password>{pwd}</password>"
            f"</query></iq>"
        )
        sock.sendall(iq.encode())
        reply = _recv_until(sock, b"</iq>")
        text = reply.decode(errors="replace")
        if re.search(r"type=['\"]error['\"]", text):
            raise XmppRegisterError("registration rejected (account may exist or IBR disabled)")
        if "registered" in text or re.search(r"type=['\"]result['\"]", text):
            return xmpp_domain
        raise XmppRegisterError("unexpected registration reply")
    finally:
        try:
            sock.sendall(b"</stream:stream>")
        except OSError:
            pass
        sock.close()