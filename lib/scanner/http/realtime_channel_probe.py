#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pusher and Liveblocks realtime channel enumeration using leaked credentials."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

from lib.scanner.http.vibe_secrets_probe import mask_secret

_PUSHER_KEY_RE = re.compile(r"\b([a-f0-9]{20})\b")
_PUSHER_CLUSTER_RE = re.compile(r"(?i)(?:cluster|pusherCluster)\s*[:=]\s*['\"]([a-z0-9-]+)['\"]")
_LIVEBLOCKS_SECRET_RE = re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9_-]{20,}\b")


def discover_realtime_credentials(text: str) -> Dict[str, str]:
    creds: Dict[str, str] = {}
    body = text or ""
    for match in re.finditer(
        r"(?i)(?:NEXT_PUBLIC_)?PUSHER_(?:APP_ID|KEY|SECRET|CLUSTER)\s*[=:]\s*['\"]([^'\"]+)['\"]",
        body,
    ):
        line = match.group(0).upper()
        val = match.group(1).strip()
        if "APP_ID" in line:
            creds["pusher_app_id"] = val
        elif "SECRET" in line:
            creds["pusher_secret"] = val
        elif "CLUSTER" in line:
            creds["pusher_cluster"] = val
        else:
            creds.setdefault("pusher_key", val)
    for match in _PUSHER_CLUSTER_RE.finditer(body):
        creds.setdefault("pusher_cluster", match.group(1))
    for match in _LIVEBLOCKS_SECRET_RE.finditer(body):
        creds["liveblocks_secret"] = match.group(0)
    for match in re.finditer(
        r"(?i)LIVEBLOCKS_(?:SECRET|API)_KEY\s*[=:]\s*['\"]([^'\"]+)['\"]",
        body,
    ):
        creds["liveblocks_secret"] = match.group(1).strip()
    return creds


def enum_pusher_channels(
    session,
    app_id: str,
    key: str,
    secret: str,
    cluster: str = "mt1",
    *,
    verify_ssl: bool = True,
) -> Dict[str, Any]:
    import hashlib
    import time

    host = f"api-{cluster}.pusher.com"
    path = f"/apps/{app_id}/channels"
    method = "GET"
    body = ""
    timestamp = str(int(time.time()))
    query = f"auth_key={key}&auth_timestamp={timestamp}&auth_version=1.0"
    sig_body = f"{method}\n{path}\n{query}"
    import hmac

    signature = hmac.new(secret.encode(), sig_body.encode(), hashlib.sha256).hexdigest()
    url = f"https://{host}{path}?{query}&auth_signature={signature}"
    try:
        response = session.get(url, timeout=12, verify=verify_ssl)
    except Exception as exc:
        return {"platform": "pusher", "ok": False, "detail": str(exc)}
    if response.status_code == 401:
        return {"platform": "pusher", "ok": False, "detail": "auth_rejected"}
    if response.status_code != 200:
        return {"platform": "pusher", "ok": False, "detail": f"http_{response.status_code}"}
    try:
        data = response.json()
    except Exception:
        return {"platform": "pusher", "ok": False, "detail": "invalid_json"}
    channels = list((data.get("channels") or {}).keys())[:10]
    return {
        "platform": "pusher",
        "ok": True,
        "channels": channels,
        "channel_count": len(data.get("channels") or {}),
        "severity": "critical",
    }


def enum_liveblocks_rooms(
    session,
    secret_key: str,
    *,
    verify_ssl: bool = True,
) -> Dict[str, Any]:
    headers = {"Authorization": f"Bearer {secret_key}", "Accept": "application/json"}
    url = "https://api.liveblocks.io/v2/rooms"
    try:
        response = session.get(url, headers=headers, params={"limit": 10}, timeout=12, verify=verify_ssl)
    except Exception as exc:
        return {"platform": "liveblocks", "ok": False, "detail": str(exc)}
    if response.status_code == 401:
        return {"platform": "liveblocks", "ok": False, "detail": "key_rejected"}
    if response.status_code != 200:
        return {"platform": "liveblocks", "ok": False, "detail": f"http_{response.status_code}"}
    try:
        data = response.json()
    except Exception:
        return {"platform": "liveblocks", "ok": False, "detail": "invalid_json"}
    rooms = []
    items = data.get("data") if isinstance(data, dict) else data
    if isinstance(items, list):
        rooms = [str(r.get("id") or r)[:60] for r in items[:10] if isinstance(r, (dict, str))]
    return {
        "platform": "liveblocks",
        "ok": True,
        "rooms": rooms,
        "room_count": len(items or []) if isinstance(items, list) else 0,
        "severity": "critical",
    }


def enumerate_realtime_channels(
    session,
    homepage_html: str,
    *,
    verify_ssl: bool = True,
    pusher_app_id: str = "",
    pusher_key: str = "",
    pusher_secret: str = "",
    pusher_cluster: str = "",
    liveblocks_secret: str = "",
) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
    creds = discover_realtime_credentials(homepage_html or "")
    if pusher_app_id:
        creds["pusher_app_id"] = pusher_app_id
    if pusher_key:
        creds["pusher_key"] = pusher_key
    if pusher_secret:
        creds["pusher_secret"] = pusher_secret
    if pusher_cluster:
        creds["pusher_cluster"] = pusher_cluster
    if liveblocks_secret:
        creds["liveblocks_secret"] = liveblocks_secret

    findings: List[Dict[str, Any]] = []
    app_id = creds.get("pusher_app_id") or ""
    key = creds.get("pusher_key") or ""
    secret = creds.get("pusher_secret") or ""
    cluster = creds.get("pusher_cluster") or "mt1"
    if app_id and key and secret:
        hit = enum_pusher_channels(session, app_id, key, secret, cluster, verify_ssl=verify_ssl)
        hit["key_masked"] = mask_secret(secret)
        findings.append(hit)

    lb = creds.get("liveblocks_secret") or ""
    if lb:
        hit = enum_liveblocks_rooms(session, lb, verify_ssl=verify_ssl)
        hit["key_masked"] = mask_secret(lb)
        findings.append(hit)

    return findings, creds


__all__ = [
    "discover_realtime_credentials",
    "enumerate_realtime_channels",
    "enum_liveblocks_rooms",
    "enum_pusher_channels",
]
