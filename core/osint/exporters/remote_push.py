#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Retry helpers for remote MISP / OpenCTI push operations."""

from __future__ import annotations

import time
from typing import Any, Callable, Dict, Optional


def push_with_retry(
    push_fn: Callable[[], Dict[str, Any]],
    *,
    max_attempts: int = 3,
    backoff_base: float = 1.5,
    retry_on_status: Optional[set] = None,
) -> Dict[str, Any]:
    """
    Retry a push callable with exponential backoff.

    Retries on network errors and selected HTTP status codes (429, 502, 503, 504).
    """
    retry_status = retry_on_status or {429, 502, 503, 504}
    last: Dict[str, Any] = {"ok": False, "error": "no attempt"}
    for attempt in range(1, max(1, max_attempts) + 1):
        try:
            result = push_fn()
        except OSError as exc:
            result = {"ok": False, "error": str(exc)}
        last = dict(result) if isinstance(result, dict) else {"ok": False, "error": str(result)}
        last["attempt"] = attempt
        if last.get("ok"):
            return last
        status = last.get("status")
        retriable = status in retry_status or not last.get("ok")
        if attempt >= max_attempts or not retriable:
            break
        delay = backoff_base ** (attempt - 1)
        last["retry_after_s"] = delay
        time.sleep(delay)
    last["attempts"] = attempt
    return last
