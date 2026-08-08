#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Firebase Realtime Database rules audit and path enumeration."""

from __future__ import annotations

import json
import re
from typing import Any, Callable, Dict, List, Optional, Tuple

_RTDB_URL_RE = re.compile(
    r"""(?i)(?:databaseURL|database_url)\s*[:=]\s*["'](https?://[^"']+(?:firebaseio\.com|firebasedatabase\.app)[^"']*)["']""",
)
_RTDB_HOST_RE = re.compile(
    r"https?://([a-z0-9.-]+(?:firebaseio\.com|firebasedatabase\.app))",
    re.I,
)

_COMMON_PATHS = (
    "/users",
    "/user",
    "/profiles",
    "/profile",
    "/accounts",
    "/account",
    "/admin",
    "/admins",
    "/messages",
    "/posts",
    "/orders",
    "/customers",
    "/config",
    "/settings",
    "/public",
    "/private",
    "/chats",
    "/notifications",
)

_RULES_PATHS = (
    "/.settings/rules.json",
    "/.settings/owner.json",
)


def discover_rtdb_url(text: str) -> str:
    body = text or ""
    for match in _RTDB_URL_RE.finditer(body):
        return match.group(1).rstrip("/")
    for match in _RTDB_HOST_RE.finditer(body):
        return f"https://{match.group(1)}".rstrip("/")
    return ""


def _permission_denied(data: Any) -> bool:
    if not isinstance(data, dict):
        return False
    err = data.get("error")
    if isinstance(err, str):
        return "permission" in err.lower() or "denied" in err.lower()
    if isinstance(err, dict):
        blob = json.dumps(err).lower()
        return "permission" in blob or "denied" in blob
    return False


def probe_rtdb_path_session(
    session,
    base: str,
    subpath: str,
    *,
    verify_ssl: bool = True,
) -> Optional[Dict[str, Any]]:
    root = base.rstrip("/")
    path = subpath if subpath.startswith("/") else f"/{subpath}"
    url = f"{root}{path}/.json?shallow=true&limitToFirst=5"
    try:
        response = session.get(url, timeout=10, verify=verify_ssl)
    except Exception:
        return None
    status = int(getattr(response, "status_code", 0) or 0)
    text = str(getattr(response, "text", "") or "")
    try:
        data = json.loads(text) if text.strip() else None
    except Exception:
        data = None
    if status in (401, 403) or status != 200:
        return None
    if _permission_denied(data):
        return None
    keys = list(data.keys())[:8] if isinstance(data, dict) else []
    return {
        "path": path,
        "kind": "rtdb_public_read",
        "status_code": status,
        "child_keys": keys,
        "preview": text[:300],
        "severity": "critical" if path in ("/users", "/admin", "/accounts", "/private") else "high",
    }


def probe_rtdb_path(
    http_request: Callable[..., Any],
    base: str,
    subpath: str,
) -> Optional[Dict[str, Any]]:
    root = base.rstrip("/")
    path = subpath if subpath.startswith("/") else f"/{subpath}"
    url_path = f"{path}/.json?shallow=true&limitToFirst=5"
    response = http_request(method="GET", path=url_path, allow_redirects=True, timeout=10)
    if not response:
        return None
    status = int(getattr(response, "status_code", 0) or 0)
    text = str(getattr(response, "text", "") or "")
    try:
        data = json.loads(text) if text.strip() else None
    except Exception:
        data = None
    if status in (401, 403):
        return None
    if status != 200:
        return None
    if _permission_denied(data):
        return None
    keys = list(data.keys())[:8] if isinstance(data, dict) else []
    return {
        "path": path,
        "kind": "rtdb_public_read",
        "status_code": status,
        "child_keys": keys,
        "preview": text[:300],
        "severity": "critical" if path in ("/users", "/admin", "/accounts", "/private") else "high",
    }


def probe_rtdb_rules_session(
    session,
    base: str,
    *,
    verify_ssl: bool = True,
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    root = base.rstrip("/")
    for rules_path in _RULES_PATHS:
        url = f"{root}{rules_path}"
        try:
            response = session.get(url, timeout=10, verify=verify_ssl)
        except Exception:
            continue
        if int(getattr(response, "status_code", 0) or 0) != 200:
            continue
        text = str(getattr(response, "text", "") or "")
        if not text.strip():
            continue
        weak = []
        compact = lowered = text.lower().replace(" ", "")
        if '"auth"==null' in compact or '.read":true' in compact or '.read": true' in text.lower():
            weak.append("open_read_rule")
        if '"write"' in text.lower() and "true" in text.lower():
            weak.append("permissive_write_rule")
        findings.append(
            {
                "path": rules_path,
                "kind": "rtdb_rules_exposed",
                "weak_rules": weak,
                "preview": text[:500],
                "severity": "critical" if weak else "high",
            }
        )
    return findings


def probe_rtdb_rules(
    http_request: Callable[..., Any],
    base: str,
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    root = base.rstrip("/")
    for rules_path in _RULES_PATHS:
        response = http_request(method="GET", path=rules_path, allow_redirects=False, timeout=10)
        if not response or int(getattr(response, "status_code", 0) or 0) != 200:
            continue
        text = str(getattr(response, "text", "") or "")
        if not text.strip():
            continue
        weak = []
        compact = text.lower().replace(" ", "")
        if '"auth"==null' in compact or '.read":true' in compact:
            weak.append("open_read_rule")
        if '"write"' in text.lower() and "true" in text.lower():
            weak.append("permissive_write_rule")
        findings.append(
            {
                "path": rules_path,
                "kind": "rtdb_rules_exposed",
                "weak_rules": weak,
                "preview": text[:500],
                "severity": "critical" if weak else "high",
            }
        )
    return findings


def audit_rtdb_surface_session(
    session,
    base: str,
    *,
    verify_ssl: bool = True,
    extra_paths: Optional[List[str]] = None,
) -> Tuple[List[Dict[str, Any]], str]:
    if not base:
        return [], ""
    root = base.rstrip("/")
    if not root.startswith("http"):
        root = f"https://{root}"
    findings: List[Dict[str, Any]] = []
    findings.extend(probe_rtdb_rules_session(session, root, verify_ssl=verify_ssl))

    root_hit = probe_rtdb_path_session(session, root, "/", verify_ssl=verify_ssl)
    if root_hit:
        root_hit["kind"] = "rtdb_root_public_read"
        findings.append(root_hit)

    paths = list(_COMMON_PATHS)
    if extra_paths:
        paths.extend(extra_paths)
    seen = set()
    for sub in paths:
        if sub in seen:
            continue
        seen.add(sub)
        hit = probe_rtdb_path_session(session, root, sub, verify_ssl=verify_ssl)
        if hit:
            findings.append(hit)
    return findings, root


def audit_rtdb_surface(
    http_request: Callable[..., Any],
    base: str,
    *,
    extra_paths: Optional[List[str]] = None,
) -> Tuple[List[Dict[str, Any]], str]:
    if not base:
        return [], ""
    root = base.rstrip("/")
    if not root.startswith("http"):
        root = f"https://{root}"
    findings: List[Dict[str, Any]] = []
    findings.extend(probe_rtdb_rules(http_request, root))

    root_hit = probe_rtdb_path(http_request, root, "/")
    if root_hit:
        root_hit["kind"] = "rtdb_root_public_read"
        findings.append(root_hit)

    paths = list(_COMMON_PATHS)
    if extra_paths:
        paths.extend(extra_paths)
    seen = set()
    for sub in paths:
        if sub in seen:
            continue
        seen.add(sub)
        hit = probe_rtdb_path(http_request, root, sub)
        if hit:
            findings.append(hit)
    return findings, root


__all__ = [
    "audit_rtdb_surface",
    "audit_rtdb_surface_session",
    "discover_rtdb_url",
    "probe_rtdb_path",
    "probe_rtdb_path_session",
    "probe_rtdb_rules",
    "probe_rtdb_rules_session",
]
