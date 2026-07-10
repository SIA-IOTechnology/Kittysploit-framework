#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Heuristics to extract real secrets from JS/source-map content (not i18n labels)."""

from __future__ import annotations

import re
from typing import Dict, List

SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"""(?i)(api[_-]?key)\s*[:=]\s*["']([^"']{8,})["']"""), "api_key"),
    (re.compile(r"""(?i)(client[_-]?secret)\s*[:=]\s*["']([^"']{8,})["']"""), "client_secret"),
    (re.compile(r"""(?i)(secret[_-]?key)\s*[:=]\s*["']([^"']{8,})["']"""), "secret_key"),
    (re.compile(r"""(?i)(access[_-]?token|auth[_-]?token)\s*[:=]\s*["']([^"']{12,})["']"""), "token"),
    (re.compile(r"""(?i)(password|passwd)\s*[:=]\s*["']([^"'\s]{12,})["']"""), "password"),
    (re.compile(r"""(?i)authorization\s*[:=]\s*["']Bearer\s+([A-Za-z0-9._\-+/=]{12,})["']"""), "bearer"),
)

I18N_SOURCE_MARKERS = (
    "/strings/",
    "/string/",
    "/locale/",
    "/locales/",
    "/i18n/",
    "/translations/",
    "/messages/",
    "/lang/",
    "/copy/",
    ".strings.",
)

# Analytics / telemetry modules — event names, not credential stores.
LOW_SIGNAL_SOURCE_MARKERS = (
    "mixpanel",
    "analytics",
    "segment.",
    "/tracking/",
    "telemetry",
    "amplitude",
    "datadog",
    "metrics",
)

# Known non-secret slugs (error codes, i18n keys, event names).
NOISE_SECRET_VALUES = frozenset({
    "invalid_password",
    "wrong_password",
    "current_password",
    "forgot_password",
    "reset_password",
    "password_reset",
    "incorrect_password",
    "password123",
    "changeme",
    "placeholder",
    "undefined",
    "null",
    "true",
    "false",
})

SLUG_VALUE_RX = re.compile(r"^[a-z][a-z0-9]*(_[a-z0-9]+)+$")
EVENT_SLUG_RX = re.compile(
    r"^(invalid|wrong|incorrect|failed|error|bad|missing|empty|expired)_",
    re.IGNORECASE,
)

UI_VALUE_PREFIXES = (
    "if you ",
    "please ",
    "enter ",
    "invalid ",
    "current ",
    "your ",
    "forgot ",
    "must ",
    "should ",
    "click ",
    "the ",
    "a ",
    "an ",
)

JWT_PREFIX = "eyJ"
AWS_KEY_PREFIX = "AKIA"
SK_PREFIXES = ("sk_live_", "sk_test_", "pk_live_", "pk_test_")


def _looks_like_ui_copy(value: str) -> bool:
    text = str(value or "").strip()
    if not text:
        return True
    low = text.lower()
    if any(low.startswith(prefix) for prefix in UI_VALUE_PREFIXES):
        return True
    if " " in text and len(text.split()) >= 3:
        return True
    if text.endswith("?") or text.endswith("!"):
        return True
    return False


def _looks_like_credential_value(name: str, value: str) -> bool:
    text = str(value or "").strip()
    if len(text) < 8:
        return False
    if " " in text:
        return False
    if text.startswith(JWT_PREFIX) or text.startswith(AWS_KEY_PREFIX):
        return True
    if any(text.startswith(p) for p in SK_PREFIXES):
        return True
    alnum = sum(ch.isalnum() for ch in text)
    if alnum / max(1, len(text)) >= 0.85 and len(text) >= 16:
        return True
    if str(name or "").lower() in ("password", "passwd"):
        # Real leaked passwords in JS are rare; require strong shapes only.
        return _secret_entropy_ok(text) or text.startswith(JWT_PREFIX)
    return len(text) >= 12 and _secret_entropy_ok(text)


def is_low_signal_source(source_path: str) -> bool:
    low = str(source_path or "").lower().replace("\\", "/")
    return any(marker in low for marker in LOW_SIGNAL_SOURCE_MARKERS)


def _looks_like_event_slug(value: str) -> bool:
    text = str(value or "").strip()
    low = text.lower()
    if text.startswith(JWT_PREFIX) or text.startswith(AWS_KEY_PREFIX):
        return False
    if any(text.startswith(p) for p in SK_PREFIXES):
        return False
    if low in NOISE_SECRET_VALUES:
        return True
    if low.endswith("_password") or low.endswith("_token") or low.endswith("_secret"):
        return True
    if EVENT_SLUG_RX.match(low):
        return True
    # snake_case dictionary tokens (invalid_password) — not high-entropy secrets
    if SLUG_VALUE_RX.match(low) and len(low) < 32:
        return True
    return False


def _secret_entropy_ok(value: str) -> bool:
    text = str(value or "").strip()
    if len(text) < 16:
        return False
    alnum = sum(ch.isalnum() for ch in text)
    upper = sum(ch.isupper() for ch in text)
    lower = sum(ch.islower() for ch in text)
    digit = sum(ch.isdigit() for ch in text)
    symbol = len(text) - alnum
    classes = sum(1 for n in (upper, lower, digit, symbol) if n > 0)
    return classes >= 3 and alnum / max(1, len(text)) >= 0.7


def is_i18n_source(source_path: str) -> bool:
    low = str(source_path or "").lower().replace("\\", "/")
    return any(marker in low for marker in I18N_SOURCE_MARKERS)


def filter_secret_candidate(name: str, value: str, source_path: str = "") -> bool:
    if is_i18n_source(source_path):
        return False
    text = str(value or "").strip()
    if not text or len(text) < 8:
        return False
    if _looks_like_ui_copy(text) or _looks_like_event_slug(text):
        return False
    low_name = str(name or "").lower()
    if is_low_signal_source(source_path) and low_name in ("password", "passwd", "token"):
        # mixpanel.js + password: "invalid_password" → analytics event, ignore
        return False
    return _looks_like_credential_value(name, text)


def extract_secret_hints(body: str, source_path: str = "", *, max_hints: int = 80) -> List[Dict[str, str]]:
    if not body:
        return []
    hints: List[Dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for rx, default_name in SECRET_PATTERNS:
        for match in rx.finditer(body):
            groups = match.groups()
            if len(groups) == 2:
                name, value = groups[0], groups[1]
            else:
                name, value = default_name, groups[0]
            key = (str(name).lower(), value)
            if key in seen:
                continue
            if not filter_secret_candidate(name, value, source_path):
                continue
            seen.add(key)
            hints.append({
                "name": str(name),
                "value": str(value),
                "source": str(source_path)[:240],
                "from": "sourcemap" if "webpack" in str(source_path) else "javascript",
            })
            if len(hints) >= max_hints:
                return hints
    return hints
