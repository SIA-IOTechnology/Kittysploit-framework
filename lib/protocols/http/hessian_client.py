#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Hessian 1.0 RPC over HTTP (KittySploit Http_client mixin)."""

from __future__ import annotations

import struct
from typing import Any

from lib.protocols.http.http_client import Http_client


def _encode_string(value: str) -> bytes:
    encoded = b""
    text = str(value)
    while len(text) > 32767:
        chunk = text[:32767]
        encoded += struct.pack(">cH", b"s", len(chunk)) + chunk.encode("utf-8")
        text = text[32767:]
    encoded += struct.pack(">cH", b"S", len(text)) + text.encode("utf-8")
    return encoded


def _encode_value(obj: Any) -> bytes:
    if obj is None:
        return b"N"
    if isinstance(obj, bool):
        return b"T" if obj else b"F"
    if isinstance(obj, int):
        return struct.pack(">cl", b"I", int(obj))
    if isinstance(obj, float):
        return struct.pack(">cd", b"D", float(obj))
    if isinstance(obj, dict):
        body = b"M"
        for key, val in obj.items():
            body += _encode_string(str(key))
            body += _encode_value(val)
        return body + b"z"
    if isinstance(obj, (list, tuple)):
        body = struct.pack(">2cl", b"V", b"l", -1)
        for item in obj:
            body += _encode_value(item)
        return body + b"z"
    if isinstance(obj, (bytes, bytearray)):
        raw = bytes(obj)
        out = b""
        while len(raw) > 65535:
            out += struct.pack(">cH", b"b", 65535) + raw[:65535]
            raw = raw[65535:]
        return out + struct.pack(">cH", b"B", len(raw)) + raw
    return _encode_string(str(obj))


def encode_hessian1_call(method: str, args: list[Any]) -> bytes:
    """Build a Hessian 1.0 call envelope (Caucho / python-hessian compatible)."""
    method_b = method.encode("utf-8")
    packet = b"c\x01\x00"
    packet += b"m" + struct.pack(">H", len(method_b)) + method_b
    for arg in args:
        packet += _encode_value(arg)
    packet += b"z"
    return packet


class Hessian_client(Http_client):
    """Mixin: POST Hessian 1.0 calls via the framework HTTP client (proxy/TLS aware)."""

    hessian_content_type = "application/x-hessian"

    def encode_hessian1_call(self, method: str, args: list[Any]) -> bytes:
        return encode_hessian1_call(method, args)

    def hessian_call(
        self,
        path: str,
        method: str,
        *args: Any,
        content_type: str | None = None,
    ):
        body = self.encode_hessian1_call(method, list(args))
        headers = {"Content-Type": content_type or self.hessian_content_type}
        return self.http_request(
            method="POST",
            path=path,
            data=body,
            headers=headers,
            allow_redirects=False,
        )
