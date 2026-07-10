#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Beacon interval + jitter helpers."""

from __future__ import annotations

import random
from typing import Iterable, List, Optional


def jitter_seconds(base: float, jitter_percent: float) -> float:
    """Return *base* +/- *jitter_percent* percent (minimum 0.5s)."""
    base = max(0.5, float(base))
    pct = max(0.0, min(100.0, float(jitter_percent))) / 100.0
    if pct <= 0:
        return base
    spread = base * pct
    return max(0.5, base + random.uniform(-spread, spread))


def compute_poll_delay(
    base: float,
    jitter_percent: float,
    *,
    server_hint: Optional[float] = None,
) -> float:
    """Pick next poll delay; honour server hint when provided."""
    if server_hint is not None and float(server_hint) > 0:
        return jitter_seconds(float(server_hint), jitter_percent * 0.5)
    return jitter_seconds(base, jitter_percent)


def pick_decoy_path(paths: Iterable[str]) -> str:
    items: List[str] = [p.strip() for p in paths if str(p).strip()]
    if not items:
        return "/"
    return random.choice(items)


def pad_response(body: str, min_size: int = 0) -> str:
    """Pad JSON/text response to reduce length-based fingerprinting."""
    min_size = max(0, int(min_size))
    if len(body) >= min_size:
        return body
    pad_len = min_size - len(body)
    if body.endswith("}"):
        return body[:-1] + f',"pad":"{"x" * pad_len}"}}'
    return body + (" " * pad_len)
