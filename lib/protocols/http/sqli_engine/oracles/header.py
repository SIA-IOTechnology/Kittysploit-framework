#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""HTTP header SQLi probes (Cookie, Referer, X-Forwarded-For)."""

from __future__ import annotations

from typing import Callable, Optional, Tuple

from ..constants import DETECTION_CONFIDENCE
from ..fingerprint import evidence_snippet, fingerprint_dbms, match_sqli_error
from ..oracle import HttpParameterOracle
from ..techniques import TechniqueHit

HEADER_PROBE_NAMES = ("X-Forwarded-For", "Referer", "Cookie")

_LOGIN_PATH_HINTS = ("login", "signin", "auth", "session", "admin")


def _is_login_context(path: str = "", url: str = "") -> bool:
    p = (path or url or "").lower()
    return any(h in p for h in _LOGIN_PATH_HINTS)


def _header_error_probes() -> Tuple[Tuple[str, str], ...]:
    return (
        ("127.0.0.1'", "XFF single-quote"),
        ("' OR '1'='2", "quote OR false"),
    )


def probe_header_sqli(
    send_with_header: Callable[[str, str], Tuple[object, float]],
    header_name: str,
    *,
    original: str = "127.0.0.1",
) -> Optional[TechniqueHit]:
    """
    Probe one HTTP header for error-based SQLi.

    ``send_with_header(header_name, value)`` → ``(response, elapsed)``.
    """
    def send_wrapped(payload: str, timeout=None):
        return send_with_header(header_name, payload)

    oracle = HttpParameterOracle(original_value=original, send_payload=send_wrapped)
    oracle.baseline()

    for payload, label in _header_error_probes():
        resp = oracle.send(payload)
        token = match_sqli_error(resp.text)
        if token:
            return TechniqueHit(
                technique="error",
                payload=payload,
                label=f"{header_name}: {label}",
                confidence=DETECTION_CONFIDENCE["error"],
                evidence=evidence_snippet(resp.text, token),
                dbms=fingerprint_dbms(resp.text),
                indicators=[f"Header {header_name} SQL error"],
                status_code=resp.status_code,
                response_time=resp.elapsed,
                response_length=resp.length,
            )
    return None


def probe_login_headers(
    send_with_header: Callable[[str, str], Tuple[object, float]],
    *,
    path: str = "",
    url: str = "",
) -> Optional[TechniqueHit]:
    """Try header probes on login-like pages (first hit wins)."""
    if not _is_login_context(path, url):
        return None
    for header in HEADER_PROBE_NAMES:
        hit = probe_header_sqli(send_with_header, header)
        if hit:
            return hit
    return None
