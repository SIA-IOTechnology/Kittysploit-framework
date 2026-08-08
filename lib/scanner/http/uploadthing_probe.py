#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""UploadThing secret key discovery and file API abuse."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Tuple

from lib.scanner.http.vibe_secrets_probe import mask_secret

_UT_SECRET_RE = re.compile(r"\bsk_(live|test)_[A-Za-z0-9]{20,}\b")
_UT_APP_RE = re.compile(
    r"(?i)(?:UPLOADTHING_(?:APP_ID|SECRET|TOKEN)|uploadthingAppId)\s*[=:]\s*['\"]([^'\"]+)['\"]",
)


def discover_uploadthing_credentials(text: str) -> Dict[str, str]:
    creds: Dict[str, str] = {}
    body = text or ""
    for match in _UT_APP_RE.finditer(body):
        line = match.group(0).upper()
        val = match.group(1).strip()
        if "APP" in line:
            creds["app_id"] = val
        else:
            creds["secret_key"] = val
    for match in _UT_SECRET_RE.finditer(body):
        key = match.group(0)
        if "uploadthing" in body.lower() or "UPLOADTHING" in body:
            creds["secret_key"] = key
    return creds


def enum_uploadthing_files(
    session,
    secret_key: str,
    *,
    verify_ssl: bool = True,
) -> Dict[str, Any]:
    url = "https://api.uploadthing.com/v6/listFiles"
    headers = {
        "X-Uploadthing-Api-Key": secret_key,
        "Content-Type": "application/json",
    }
    payload = {"limit": 10}
    try:
        response = session.post(url, headers=headers, json=payload, timeout=12, verify=verify_ssl)
    except Exception as exc:
        return {"platform": "uploadthing", "ok": False, "detail": str(exc)}
    if response.status_code == 401:
        return {"platform": "uploadthing", "ok": False, "detail": "key_rejected"}
    if response.status_code != 200:
        return {"platform": "uploadthing", "ok": False, "detail": f"http_{response.status_code}"}
    try:
        data = response.json()
    except Exception:
        return {"platform": "uploadthing", "ok": False, "detail": "invalid_json"}
    files = data.get("files") if isinstance(data, dict) else []
    names = [str(f.get("name") or f.get("key") or "")[:60] for f in (files or [])[:10] if isinstance(f, dict)]
    return {
        "platform": "uploadthing",
        "ok": True,
        "kind": "uploadthing_files_listed",
        "file_count": len(files or []),
        "sample_files": names,
        "severity": "critical",
    }


def enum_uploadthing_usage(
    session,
    secret_key: str,
    *,
    verify_ssl: bool = True,
) -> Dict[str, Any]:
    url = "https://api.uploadthing.com/v6/getUsageInfo"
    headers = {"X-Uploadthing-Api-Key": secret_key}
    try:
        response = session.get(url, headers=headers, timeout=12, verify=verify_ssl)
    except Exception as exc:
        return {"platform": "uploadthing", "ok": False, "detail": str(exc)}
    if response.status_code != 200:
        return {"platform": "uploadthing", "ok": False, "detail": f"http_{response.status_code}"}
    return {
        "platform": "uploadthing",
        "ok": True,
        "kind": "uploadthing_usage_info",
        "preview": str(response.text or "")[:300],
        "severity": "high",
    }


def enumerate_uploadthing(
    session,
    homepage_html: str,
    *,
    verify_ssl: bool = True,
    secret_key: str = "",
) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
    creds = discover_uploadthing_credentials(homepage_html or "")
    if secret_key:
        creds["secret_key"] = secret_key

    findings: List[Dict[str, Any]] = []
    key = creds.get("secret_key") or ""
    if not key:
        return findings, creds

    files = enum_uploadthing_files(session, key, verify_ssl=verify_ssl)
    files["key_masked"] = mask_secret(key)
    if files.get("ok"):
        findings.append(files)
        usage = enum_uploadthing_usage(session, key, verify_ssl=verify_ssl)
        if usage.get("ok"):
            findings.append(usage)
    else:
        findings.append(files)
    return findings, creds


__all__ = [
    "discover_uploadthing_credentials",
    "enumerate_uploadthing",
    "enum_uploadthing_files",
]
