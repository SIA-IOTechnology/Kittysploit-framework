#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""In-memory cache for identical LLM planning requests within a process."""

from __future__ import annotations

import hashlib
import json
import threading
from typing import Any, Dict, Optional


class LLMResponseCache:
    """Thread-safe LRU-ish cache for JSON LLM planning responses."""

    def __init__(self, max_entries: int = 64) -> None:
        self._max_entries = max(1, int(max_entries or 1))
        self._lock = threading.Lock()
        self._store: Dict[str, Dict[str, Any]] = {}
        self._order: list[str] = []

    @staticmethod
    def cache_key(
        *,
        phase: str,
        model: str,
        endpoint: str,
        goal: str,
        payload: Dict[str, Any],
    ) -> str:
        blob = json.dumps(
            {
                "phase": phase,
                "model": model,
                "endpoint": endpoint,
                "goal": goal,
                "payload": payload,
            },
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:32]

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            return dict(entry)

    def put(self, key: str, value: Dict[str, Any]) -> None:
        with self._lock:
            if key in self._store:
                try:
                    self._order.remove(key)
                except ValueError:
                    pass
            elif len(self._order) >= self._max_entries:
                oldest = self._order.pop(0)
                self._store.pop(oldest, None)
            self._store[key] = dict(value)
            self._order.append(key)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()
            self._order.clear()


_DEFAULT_CACHE = LLMResponseCache()


def get_llm_response_cache() -> LLMResponseCache:
    return _DEFAULT_CACHE
