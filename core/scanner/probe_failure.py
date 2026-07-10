#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Shared helpers for expected connectivity failures during passive discovery."""

from __future__ import annotations

_SOFT_PROBE_FAILURE_MARKERS = (
    "connection refused",
    "failed to establish a new connection",
    "name or service not known",
    "name resolution",
    "max retries exceeded",
    "timed out",
    "timeout",
    "connection reset",
    "no route to host",
    "network is unreachable",
    "connection aborted",
    "eof occurred",
    "connection error",
    "tcp port closed",
    "read timed out",
)


def is_soft_probe_failure(exc: Exception | str) -> bool:
    """Connectivity/timeouts during discovery are expected — not operator errors."""
    msg = str(exc or "").lower()
    return any(marker in msg for marker in _SOFT_PROBE_FAILURE_MARKERS)
