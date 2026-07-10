#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Normalize scanner module targets that may be passed as full URLs."""

from __future__ import annotations

from typing import Optional, Tuple
from urllib.parse import urlparse


def normalize_scanner_target(raw: str) -> Tuple[str, Optional[int], Optional[bool]]:
    """
    Return (host, port, ssl_hint) from a scanner target string.

    Bare hostnames/IPs are returned unchanged with port/ssl_hint=None.
    """
    value = str(raw or "").strip()
    if not value or "://" not in value:
        return value, None, None

    parsed = urlparse(value)
    host = (parsed.hostname or "").strip()
    if not host:
        return value, None, None

    port = parsed.port
    scheme = (parsed.scheme or "").lower()
    if port is None:
        if scheme == "https":
            port = 443
        elif scheme == "http":
            port = 80

    ssl_hint: Optional[bool] = None
    if scheme == "https":
        ssl_hint = True
    elif scheme == "http":
        ssl_hint = False

    return host, port, ssl_hint


def apply_url_target_to_variables(variables: dict) -> dict:
    """Normalize workflow variables when ``target`` is a full URL."""
    if not isinstance(variables, dict):
        return variables
    raw = str(variables.get("target") or "").strip()
    if not raw or "://" not in raw:
        return variables

    host, url_port, url_ssl = normalize_scanner_target(raw)
    if not host:
        return variables

    out = dict(variables)
    out["target"] = host
    if url_port is not None:
        for key in ("http_port", "port"):
            if key in out:
                out[key] = str(url_port)
    if url_ssl is not None and "ssl" in out:
        out["ssl"] = "true" if url_ssl else "false"
    return out
