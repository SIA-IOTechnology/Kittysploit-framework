#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Persistent module metadata index.

Stores lightweight per-module fields so discovery/filtering can skip
re-parsing thousands of Python sources on every ``scanner -u``.
"""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from core.utils.module_static_metadata import extract_module_search_metadata

INDEX_VERSION = 1
_LOCK = threading.RLock()
_MEMORY: Optional[Dict[str, Any]] = None


def default_index_path() -> Path:
    return Path.home() / ".kittysploit" / "cache" / "module_index.json"


def _file_stamp(path: str) -> Tuple[int, int]:
    try:
        st = os.stat(path)
        return int(st.st_mtime_ns), int(st.st_size)
    except OSError:
        return 0, 0


def _empty_index() -> Dict[str, Any]:
    return {
        "version": INDEX_VERSION,
        "updated_at": 0.0,
        "modules": {},  # module_path -> entry
    }


def load_index(index_path: Optional[Path] = None) -> Dict[str, Any]:
    global _MEMORY
    path = index_path or default_index_path()
    with _LOCK:
        if _MEMORY is not None:
            return _MEMORY
        if not path.is_file():
            _MEMORY = _empty_index()
            return _MEMORY
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict) or data.get("version") != INDEX_VERSION:
                _MEMORY = _empty_index()
            else:
                data.setdefault("modules", {})
                _MEMORY = data
        except Exception:
            _MEMORY = _empty_index()
        return _MEMORY


def save_index(index: Dict[str, Any], index_path: Optional[Path] = None) -> None:
    path = index_path or default_index_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    index["updated_at"] = time.time()
    index["version"] = INDEX_VERSION
    tmp = path.with_suffix(".tmp")
    payload = json.dumps(index, ensure_ascii=False, separators=(",", ":"))
    tmp.write_text(payload, encoding="utf-8")
    tmp.replace(path)
    global _MEMORY
    with _LOCK:
        _MEMORY = index


def invalidate_memory_index() -> None:
    global _MEMORY
    with _LOCK:
        _MEMORY = None


def build_entry(module_path: str, file_path: str) -> Dict[str, Any]:
    mtime_ns, size = _file_stamp(file_path)
    meta = {}
    try:
        meta = extract_module_search_metadata(file_path) or {}
    except Exception:
        meta = {}
    parts = module_path.split("/")
    family = parts[1] if len(parts) > 1 else ""
    return {
        "path": module_path,
        "file": file_path,
        "mtime_ns": mtime_ns,
        "size": size,
        "name": meta.get("name") or module_path,
        "description": meta.get("description") or "",
        "author": meta.get("author") or "",
        "tags": list(meta.get("tags") or []),
        "cve": meta.get("cve") or "",
        "family": family,
    }


def entry_is_fresh(entry: Dict[str, Any], file_path: str) -> bool:
    mtime_ns, size = _file_stamp(file_path)
    return (
        int(entry.get("mtime_ns") or 0) == mtime_ns
        and int(entry.get("size") or 0) == size
        and str(entry.get("file") or "") == file_path
    )


def sync_index(
    discovered: Dict[str, str],
    *,
    index_path: Optional[Path] = None,
    progress_every: int = 0,
    progress_cb=None,
) -> Dict[str, Any]:
    """
    Refresh the persistent index from a path→file discovery map.

    Only re-parses files whose mtime/size changed.
    """
    index = load_index(index_path)
    modules = dict(index.get("modules") or {})
    seen = set()
    rebuilt = 0
    reused = 0

    items = list(discovered.items())
    for i, (module_path, file_path) in enumerate(items, 1):
        seen.add(module_path)
        old = modules.get(module_path)
        if old and entry_is_fresh(old, file_path):
            reused += 1
            continue
        modules[module_path] = build_entry(module_path, file_path)
        rebuilt += 1
        if progress_every and progress_cb and i % progress_every == 0:
            progress_cb(i, len(items), rebuilt, reused)

    # Drop deleted modules
    for stale in [p for p in modules.keys() if p not in seen]:
        modules.pop(stale, None)

    index["modules"] = modules
    index["stats"] = {"rebuilt": rebuilt, "reused": reused, "total": len(modules)}
    save_index(index, index_path)
    return index


def get_scanner_modules(
    discovered: Dict[str, str],
    *,
    index_path: Optional[Path] = None,
    force_rebuild: bool = False,
    progress_cb=None,
) -> List[Dict[str, Any]]:
    """Return scanner module metadata rows, syncing the index as needed."""
    if force_rebuild:
        invalidate_memory_index()
    index = load_index(index_path)
    modules = index.get("modules") or {}

    # Fast path: if every discovered scanner path is present and fresh, reuse.
    scanner_paths = {p: f for p, f in discovered.items() if p.startswith("scanner/")}
    needs_sync = force_rebuild or not modules
    if not needs_sync:
        for path, file_path in scanner_paths.items():
            entry = modules.get(path)
            if not entry or not entry_is_fresh(entry, file_path):
                needs_sync = True
                break
        # Also sync if index has many stale scanner entries (deleted files)
        if not needs_sync:
            indexed_scanners = [p for p in modules if p.startswith("scanner/")]
            if len(indexed_scanners) != len(scanner_paths):
                needs_sync = True

    if needs_sync:
        # Index only scanner/* — this index is for bulk scanner discovery
        sync_index(
            scanner_paths,
            index_path=index_path,
            progress_every=500 if progress_cb else 0,
            progress_cb=progress_cb,
        )
        index = load_index(index_path)
        modules = index.get("modules") or {}

    rows: List[Dict[str, Any]] = []
    for path, file_path in sorted(scanner_paths.items()):
        entry = modules.get(path) or build_entry(path, file_path)
        rows.append(
            {
                "path": path,
                "file_path": file_path,
                "name": entry.get("name") or path,
                "description": entry.get("description") or "",
                "author": entry.get("author") or "",
                "tags": list(entry.get("tags") or []),
                "cve": entry.get("cve") or "",
                "family": entry.get("family") or "",
            }
        )
    return rows
