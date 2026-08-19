#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Agent-side encrypted local store for background task results.

This module is designed to be embedded in Python implants. It keeps task output
on disk in encrypted form and survives short C2 outages.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from typing import Any, Dict, List, Optional


def _derive_key(secret: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8", errors="replace"), salt, 120_000, dklen=32)


def _xor_stream(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    out = bytearray(len(data))
    for i, b in enumerate(data):
        out[i] = b ^ key[i % len(key)]
    return bytes(out)


class AgentStore:
    """Minimal encrypted key-value store for implant-side background tasks."""

    VERSION = 1

    def __init__(self, path: str, secret: str):
        self.path = path
        self.secret = secret or "kitty-agent-store"
        self._cache: Dict[str, Any] = {}
        self._loaded = False

    def _load(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        if not os.path.isfile(self.path):
            self._cache = {"version": self.VERSION, "tasks": {}}
            return
        try:
            with open(self.path, "rb") as fh:
                blob = fh.read()
            if len(blob) < 32:
                return
            salt, payload = blob[:16], blob[16:]
            key = _derive_key(self.secret, salt)
            plain = _xor_stream(payload, key)
            data = json.loads(plain.decode("utf-8", errors="replace"))
            if isinstance(data, dict):
                self._cache = data
        except Exception:
            self._cache = {"version": self.VERSION, "tasks": {}}

    def _save(self) -> None:
        self._cache.setdefault("version", self.VERSION)
        self._cache.setdefault("tasks", {})
        salt = os.urandom(16)
        key = _derive_key(self.secret, salt)
        plain = json.dumps(self._cache, separators=(",", ":")).encode("utf-8")
        payload = _xor_stream(plain, key)
        directory = os.path.dirname(self.path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "wb") as fh:
            fh.write(salt + payload)
        os.replace(tmp, self.path)

    def put_task_result(self, task_id: str, result: Any) -> None:
        self._load()
        tasks = self._cache.setdefault("tasks", {})
        tasks[str(task_id)] = {
            "result": result,
            "updated_at": time.time(),
        }
        self._save()

    def get_task_result(self, task_id: str) -> Optional[Any]:
        self._load()
        entry = (self._cache.get("tasks") or {}).get(str(task_id))
        if not entry:
            return None
        return entry.get("result")

    def list_pending_tasks(self) -> List[str]:
        self._load()
        return sorted((self._cache.get("tasks") or {}).keys())

    def clear_task(self, task_id: str) -> None:
        self._load()
        tasks = self._cache.setdefault("tasks", {})
        tasks.pop(str(task_id), None)
        self._save()


def build_agent_store_bootstrap(
    store_path: str,
    secret: str,
    *,
    var_name: str = "_kitty_store",
    path_is_expression: bool = False,
) -> str:
    """Return Python source that defines a ready-to-use AgentStore instance."""
    import inspect
    import textwrap

    src = inspect.getsource(AgentStore)
    src += "\n\n"
    src += inspect.getsource(_derive_key) + "\n"
    src += inspect.getsource(_xor_stream) + "\n"
    path_arg = store_path if path_is_expression else repr(store_path)
    src += f"{var_name} = AgentStore({path_arg}, {secret!r})\n"
    return textwrap.dedent(src)
