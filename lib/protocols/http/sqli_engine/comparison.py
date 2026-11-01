#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Multi-signal HTTP response comparison for boolean SQLi (sqlmap-style stability)."""

from __future__ import annotations

import hashlib
import re
from typing import Tuple

from .oracle import ProbeResponse

_DYNAMIC_PATTERNS = (
    re.compile(r"\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}\b"),
    re.compile(r"\b\d{10,13}\b"),
    re.compile(r'csrf[_-]?token["\']?\s*[:=]\s*["\']?[a-zA-Z0-9+/=_-]{8,}'),
    re.compile(r'nonce["\']?\s*[:=]\s*["\']?[a-zA-Z0-9+/=_-]{8,}'),
    re.compile(r"\b\d+\b"),
)


def stabilize_text(text: str) -> str:
    """Strip volatile fragments so boolean diffs focus on structural content."""
    body = str(text or "")
    body = body.lower()
    for pattern in _DYNAMIC_PATTERNS:
        body = pattern.sub(" ", body)
    body = re.sub(r"\s+", " ", body).strip()
    return body


def content_digest(text: str) -> str:
    return hashlib.sha256(stabilize_text(text).encode("utf-8", "replace")).hexdigest()[:16]


def similarity(a: str, b: str) -> float:
    """Token-set Jaccard similarity on stabilized bodies."""
    ta = set(stabilize_text(a).split())
    tb = set(stabilize_text(b).split())
    if not ta and not tb:
        return 1.0
    if not ta or not tb:
        return 0.0
    inter = len(ta & tb)
    union = len(ta | tb)
    return inter / union if union else 0.0


def _status_compatible(a: int, b: int) -> bool:
    if a == b:
        return True
    if a in {0, 502, 503, 504} or b in {0, 502, 503, 504}:
        return False
    return abs(a - b) <= 1


def boolean_evidence(
    baseline: ProbeResponse,
    true_resp: ProbeResponse,
    false_resp: ProbeResponse,
) -> str:
    """
    Return human-readable evidence when true/false branches diverge meaningfully.

    Uses length, digest, and token similarity (not length alone).
    """
    if not baseline.text and baseline.status_code == 0:
        return ""
    if not true_resp.text and true_resp.status_code == 0:
        return ""
    if not false_resp.text and false_resp.status_code == 0:
        return ""

    if not _status_compatible(baseline.status_code, true_resp.status_code):
        return ""
    if not _status_compatible(true_resp.status_code, false_resp.status_code):
        return ""

    base_len = baseline.length
    true_len = true_resp.length
    false_len = false_resp.length

    sim_base_true = similarity(baseline.text, true_resp.text)
    sim_base_false = similarity(baseline.text, false_resp.text)
    sim_true_false = similarity(true_resp.text, false_resp.text)

    digest_base = content_digest(baseline.text)
    digest_true = content_digest(true_resp.text)
    digest_false = content_digest(false_resp.text)

    true_stable = sim_base_true >= 0.92 or digest_base == digest_true
    false_different = (
        sim_true_false <= 0.88
        or digest_true != digest_false
        or abs(false_len - true_len) >= max(80, int(max(true_len, false_len) * 0.08))
    )

    length_signal = (
        abs(true_len - base_len) <= max(60, int(base_len * 0.08))
        and abs(false_len - true_len) >= max(120, int(max(true_len, false_len) * 0.10))
    )

    if true_stable and false_different and (length_signal or sim_base_false <= 0.85):
        return (
            "Boolean SQLi: true branch matches baseline "
            f"(sim={sim_base_true:.2f}), false branch diverges "
            f"(sim_true_false={sim_true_false:.2f}, len {true_len}/{false_len})"
        )

    if sim_base_false >= 0.92 and sim_base_true <= 0.85 and sim_true_false <= 0.88:
        return (
            "Boolean SQLi: inverted branch drift "
            f"(sim_base_true={sim_base_true:.2f}, sim_base_false={sim_base_false:.2f})"
        )

    return ""


def union_reflection_marker(text: str, marker: str = "kspi") -> bool:
    low = str(text or "").lower()
    if marker.lower() in low:
        return True
    if "4b535049" in low:
        return True
    return False
