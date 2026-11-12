#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Typed campaign memory (guide, exploit_path, module_combo, waf_bypass, browser_chain)."""

from __future__ import annotations

import hashlib
import time
from typing import Any, Dict, List, Mapping, MutableMapping, Optional, Sequence

from interfaces.command_system.builtin.agent.redaction import sanitize_nested

DOC_TYPES = frozenset({
    "guide",
    "answer",
    "code",
    "exploit_path",
    "module_combo",
    "waf_bypass",
    "browser_chain",
})
MAX_DOCS = 256
MAX_SNIPPET = 1200


def _store(kb: MutableMapping[str, Any]) -> Dict[str, Any]:
    mem = kb.get("typed_memory")
    if not isinstance(mem, dict):
        mem = {"version": 1, "docs": []}
        kb["typed_memory"] = mem
    mem.setdefault("docs", [])
    return mem


def store_typed_memory(
    kb: MutableMapping[str, Any],
    *,
    doc_type: str,
    title: str,
    body: str,
    tags: Optional[Sequence[str]] = None,
    source: str = "",
) -> str:
    dtype = str(doc_type or "guide").strip().lower()
    if dtype not in DOC_TYPES:
        dtype = "guide"
    text = str(body or "")[:MAX_SNIPPET]
    doc_id = hashlib.sha256(f"{dtype}:{title}:{text[:80]}".encode()).hexdigest()[:16]
    row = sanitize_nested({
        "id": doc_id,
        "doc_type": dtype,
        "title": str(title or "")[:200],
        "body": text,
        "tags": [str(t)[:48] for t in (tags or []) if str(t).strip()][:12],
        "source": str(source or "")[:200],
        "ts": round(time.time(), 3),
    })
    mem = _store(kb)
    docs: List[Dict[str, Any]] = [d for d in mem.get("docs") or [] if isinstance(d, dict)]
    docs = [d for d in docs if str(d.get("id") or "") != doc_id]
    docs.append(row)
    mem["docs"] = docs[-MAX_DOCS:]
    return doc_id


def search_typed_memory(
    kb: Mapping[str, Any],
    *,
    query: str = "",
    doc_type: Optional[str] = None,
    limit: int = 8,
) -> List[Dict[str, Any]]:
    if not isinstance(kb, Mapping):
        return []
    mem = kb.get("typed_memory")
    if not isinstance(mem, dict):
        return []
    docs = [d for d in (mem.get("docs") or []) if isinstance(d, dict)]
    q = str(query or "").strip().lower()
    dtype = str(doc_type or "").strip().lower()
    out: List[Dict[str, Any]] = []
    for row in reversed(docs):
        if dtype and str(row.get("doc_type") or "") != dtype:
            continue
        if q:
            blob = " ".join(
                [
                    str(row.get("title") or ""),
                    str(row.get("body") or ""),
                    " ".join(str(t) for t in (row.get("tags") or [])),
                ]
            ).lower()
            if q not in blob and not any(tok in blob for tok in q.split()[:6] if len(tok) > 2):
                continue
        out.append({
            "id": row.get("id"),
            "doc_type": row.get("doc_type"),
            "title": row.get("title"),
            "body": str(row.get("body") or "")[:400],
            "tags": row.get("tags"),
            "source": row.get("source"),
        })
        if len(out) >= max(1, min(limit, 24)):
            break
    return out


def memory_from_module_outcome(
    kb: MutableMapping[str, Any],
    *,
    module_path: str,
    vulnerable: bool,
    phase: str = "",
    message: str = "",
) -> Optional[str]:
    """Best-effort typed store after confirmed module outcomes."""
    path = str(module_path or "")
    if not path:
        return None
    if vulnerable:
        dtype = "browser_chain" if "browser" in path else "exploit_path"
        title = f"{path} ({phase or 'phase'})"
        return store_typed_memory(
            kb,
            doc_type=dtype,
            title=title,
            body=str(message or "confirmed signal")[:MAX_SNIPPET],
            tags=[phase, path.split("/")[0] if "/" in path else path],
            source=path,
        )
    if "waf" in message.lower() or "blocked" in message.lower():
        return store_typed_memory(
            kb,
            doc_type="waf_bypass",
            title=f"blocked:{path}",
            body=message[:MAX_SNIPPET],
            source=path,
        )
    return None
