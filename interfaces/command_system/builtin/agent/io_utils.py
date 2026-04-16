#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Small JSON IO helpers for agent persistence."""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any, Dict


def load_json_dict(path: str) -> Dict[str, Any]:
    """Load a JSON object from disk and return ``{}`` on absence/invalid data."""
    try:
        if not path or not os.path.exists(path):
            return {}
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def atomic_write_json(path: str, payload: Dict[str, Any]) -> None:
    """Write JSON atomically to reduce truncated/corrupted cache files."""
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)

    fd, tmp_path = tempfile.mkstemp(prefix=".tmp_agent_", suffix=".json", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass
        raise
