#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Firestore collection rules audit and path enumeration."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

_PROJECT_RE = re.compile(
    r"""(?:projectId|project_id)\s*[:=]\s*["']([a-z0-9\-]+)["']""",
    re.I,
)
_AIZA_RE = re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")

_COMMON_COLLECTIONS = (
    "users",
    "user",
    "profiles",
    "profile",
    "accounts",
    "account",
    "posts",
    "messages",
    "orders",
    "customers",
    "products",
    "admin",
    "config",
    "settings",
    "chats",
    "notifications",
    "private",
    "public",
)


def discover_firestore_project(text: str) -> Tuple[str, str]:
    body = text or ""
    project = ""
    api_key = ""
    for match in _PROJECT_RE.finditer(body):
        project = match.group(1)
    for match in _AIZA_RE.finditer(body):
        api_key = match.group(0)
    return project, api_key


def _firestore_url(project: str, collection: str, api_key: str = "") -> str:
    base = (
        f"https://firestore.googleapis.com/v1/projects/{quote(project)}"
        f"/databases/(default)/documents/{quote(collection)}"
    )
    params = ["pageSize=5"]
    if api_key:
        params.append(f"key={quote(api_key)}")
    return f"{base}?{'&'.join(params)}"


def probe_firestore_collection(
    session,
    project: str,
    collection: str,
    api_key: str = "",
    *,
    verify_ssl: bool = True,
) -> Optional[Dict[str, Any]]:
    url = _firestore_url(project, collection, api_key)
    try:
        response = session.get(url, timeout=12, verify=verify_ssl)
    except Exception:
        return None
    status = int(getattr(response, "status_code", 0) or 0)
    text = str(getattr(response, "text", "") or "")
    if status in (401, 403) or "PERMISSION_DENIED" in text:
        return None
    if status != 200:
        return None
    doc_names: List[str] = []
    try:
        data = json.loads(text)
        for doc in (data.get("documents") or [])[:5]:
            if isinstance(doc, dict):
                name = str(doc.get("name") or "")
                doc_names.append(name.rsplit("/", 1)[-1][:40])
    except Exception:
        pass
    if not doc_names and '"documents"' not in text and text.strip() not in ("{}", ""):
        return None
    return {
        "collection": collection,
        "kind": "firestore_collection_readable",
        "status_code": status,
        "document_ids": doc_names,
        "preview": text[:400],
        "severity": "critical" if collection in ("users", "admin", "accounts", "private") else "high",
    }


def audit_firestore_rules(
    session,
    project: str,
    api_key: str = "",
    *,
    verify_ssl: bool = True,
    extra_collections: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    collections = list(_COMMON_COLLECTIONS)
    if extra_collections:
        collections.extend(extra_collections)
    seen = set()
    for coll in collections:
        if coll in seen:
            continue
        seen.add(coll)
        hit = probe_firestore_collection(session, project, coll, api_key, verify_ssl=verify_ssl)
        if hit:
            hit["project_id"] = project
            findings.append(hit)

    root_url = (
        f"https://firestore.googleapis.com/v1/projects/{quote(project)}"
        f"/databases/(default)/documents?pageSize=1"
    )
    if api_key:
        root_url += f"&key={quote(api_key)}"
    try:
        response = session.get(root_url, timeout=12, verify=verify_ssl)
        text = str(getattr(response, "text", "") or "")
        if int(getattr(response, "status_code", 0) or 0) == 200 and "PERMISSION_DENIED" not in text:
            if not any(f.get("collection") == "users" for f in findings):
                findings.insert(
                    0,
                    {
                        "collection": "(root)",
                        "kind": "firestore_root_listable",
                        "project_id": project,
                        "preview": text[:300],
                        "severity": "critical",
                    },
                )
    except Exception:
        pass
    return findings


__all__ = [
    "audit_firestore_rules",
    "discover_firestore_project",
    "probe_firestore_collection",
]
