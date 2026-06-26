#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Central redaction helpers for agent logs, checkpoints, reports, and LLM context."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


SENSITIVE_KEY_MARKERS = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "set-cookie",
    "csrf",
    "credential",
    "private_key",
    "content_preview",
    "full_content",
    "extracted_secrets",
)

SECRET_PATTERNS = (
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)?\b"),
    re.compile(
        r"(?i)\b(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*"
        r"([\"']?)[^\s,;\"']{4,}\2"
    ),
)


def is_sensitive_key(key: Any) -> bool:
    low = str(key or "").strip().lower()
    return bool(low and any(marker in low for marker in SENSITIVE_KEY_MARKERS))


def redact_text(value: Any, limit: int = 16000) -> str:
    text = str(value or "")[: max(0, int(limit))]
    for pattern in SECRET_PATTERNS:
        text = pattern.sub("[redacted]", text)
    return text


def redact_url(value: str) -> str:
    try:
        parsed = urlsplit(str(value or ""))
        if not parsed.query:
            return str(value or "")
        query = []
        for key, item in parse_qsl(parsed.query, keep_blank_values=True):
            query.append((key, "[redacted]" if is_sensitive_key(key) else redact_text(item, 512)))
        return urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path, urlencode(query), parsed.fragment)
        )
    except Exception:
        return redact_text(value)


def sanitize_nested(value: Any, parent_key: str = "", depth: int = 0) -> Any:
    if depth > 24:
        return "[truncated]"
    if is_sensitive_key(parent_key):
        return "[redacted]"
    if isinstance(value, dict):
        return {
            str(key): sanitize_nested(item, str(key), depth + 1)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple, set)):
        return [sanitize_nested(item, parent_key, depth + 1) for item in list(value)[:2000]]
    if isinstance(value, str):
        if parent_key.lower() in {"url", "final_url", "target_url"}:
            return redact_url(value)
        return redact_text(value)
    return value
