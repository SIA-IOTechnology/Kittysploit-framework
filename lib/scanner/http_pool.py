#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Shared HTTP connection pool for bulk scanner runs.

Avoids creating a requests.Session per module instance during large scans.
Provides a scan-scoped shared Session with a connection pool.
"""

from __future__ import annotations

import threading
from contextlib import contextmanager
from typing import Iterator, Optional

import requests
import urllib3
from requests.adapters import HTTPAdapter

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_lock = threading.RLock()
_active_session: Optional[requests.Session] = None
_active_depth = 0


def get_scan_session() -> Optional[requests.Session]:
    """Return the active scan-scoped session, if any."""
    return _active_session


def _build_session(pool_size: int, user_agent: str) -> requests.Session:
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
    )
    size = max(4, int(pool_size))
    adapter = HTTPAdapter(pool_connections=size, pool_maxsize=size, max_retries=0)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


@contextmanager
def scan_http_session(
    *,
    pool_size: int = 20,
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    ),
) -> Iterator[requests.Session]:
    """
    Open a shared Session for the duration of a bulk ``scanner -u`` run.

    Nested calls reuse the outer session (reference-counted).
    """
    global _active_session, _active_depth
    created = False
    with _lock:
        if _active_session is None:
            _active_session = _build_session(pool_size, user_agent)
            created = True
        _active_depth += 1
        session = _active_session
    try:
        yield session
    finally:
        with _lock:
            _active_depth = max(0, _active_depth - 1)
            if _active_depth == 0 and created and _active_session is not None:
                try:
                    _active_session.close()
                except Exception:
                    pass
                _active_session = None
