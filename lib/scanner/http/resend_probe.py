#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Resend API key discovery and email/domain enumeration."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

from lib.scanner.http.vibe_secrets_probe import mask_secret

_RESEND_KEY_RE = re.compile(r"\bre_[A-Za-z0-9_]{16,}\b")


def discover_resend_credentials(text: str) -> Dict[str, str]:
    creds: Dict[str, str] = {}
    body = text or ""
    for match in _RESEND_KEY_RE.finditer(body):
        creds["api_key"] = match.group(0)
    for match in re.finditer(
        r"(?i)(?:RESEND_(?:API_)?KEY)\s*[=:]\s*['\"]([^'\"]+)['\"]",
        body,
    ):
        creds["api_key"] = match.group(1).strip()
    return creds


def enum_resend_domains(
    session,
    api_key: str,
    *,
    verify_ssl: bool = True,
) -> Dict[str, Any]:
    url = "https://api.resend.com/domains"
    headers = {"Authorization": f"Bearer {api_key}", "Accept": "application/json"}
    try:
        response = session.get(url, headers=headers, timeout=12, verify=verify_ssl)
    except Exception as exc:
        return {"platform": "resend", "ok": False, "detail": str(exc)}
    if response.status_code == 401:
        return {"platform": "resend", "ok": False, "detail": "key_rejected"}
    if response.status_code != 200:
        return {"platform": "resend", "ok": False, "detail": f"http_{response.status_code}"}
    try:
        data = response.json()
    except Exception:
        return {"platform": "resend", "ok": False, "detail": "invalid_json"}
    items = data.get("data") if isinstance(data, dict) else data
    domains = [str(d.get("name") or "") for d in (items or [])[:10] if isinstance(d, dict)]
    return {
        "platform": "resend",
        "ok": True,
        "kind": "resend_domains_listed",
        "domains": domains,
        "count": len(items or []),
        "severity": "critical",
    }


def enum_resend_emails(
    session,
    api_key: str,
    *,
    verify_ssl: bool = True,
) -> Dict[str, Any]:
    url = "https://api.resend.com/emails"
    headers = {"Authorization": f"Bearer {api_key}", "Accept": "application/json"}
    try:
        response = session.get(url, headers=headers, timeout=12, verify=verify_ssl)
    except Exception as exc:
        return {"platform": "resend", "ok": False, "detail": str(exc)}
    if response.status_code != 200:
        return {"platform": "resend", "ok": False, "detail": f"http_{response.status_code}"}
    try:
        data = response.json()
    except Exception:
        return {"platform": "resend", "ok": False, "detail": "invalid_json"}
    items = data.get("data") if isinstance(data, dict) else data
    samples = []
    for item in (items or [])[:5]:
        if not isinstance(item, dict):
            continue
        samples.append(
            {
                "to": str(item.get("to") or "")[:80],
                "subject": str(item.get("subject") or "")[:80],
                "from": str(item.get("from") or "")[:60],
            }
        )
    return {
        "platform": "resend",
        "ok": True,
        "kind": "resend_emails_listed",
        "email_samples": samples,
        "count": len(items or []),
        "severity": "critical" if samples else "high",
    }


def enum_resend_api_keys(
    session,
    api_key: str,
    *,
    verify_ssl: bool = True,
) -> Dict[str, Any]:
    url = "https://api.resend.com/api-keys"
    headers = {"Authorization": f"Bearer {api_key}", "Accept": "application/json"}
    try:
        response = session.get(url, headers=headers, timeout=12, verify=verify_ssl)
    except Exception as exc:
        return {"platform": "resend", "ok": False, "detail": str(exc)}
    if response.status_code != 200:
        return {"platform": "resend", "ok": False, "detail": f"http_{response.status_code}"}
    return {
        "platform": "resend",
        "ok": True,
        "kind": "resend_api_keys_listed",
        "preview": str(response.text or "")[:300],
        "severity": "critical",
    }


def enumerate_resend(
    session,
    homepage_html: str,
    *,
    verify_ssl: bool = True,
    api_key: str = "",
) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
    creds = discover_resend_credentials(homepage_html or "")
    if api_key:
        creds["api_key"] = api_key

    findings: List[Dict[str, Any]] = []
    key = creds.get("api_key") or ""
    if not key:
        return findings, creds

    for fn in (enum_resend_domains, enum_resend_emails, enum_resend_api_keys):
        hit = fn(session, key, verify_ssl=verify_ssl)
        hit["key_masked"] = mask_secret(key)
        if hit.get("ok"):
            findings.append(hit)

    if not findings:
        findings.append({"platform": "resend", "ok": False, "detail": "no_api_access", "key_masked": mask_secret(key)})
    return findings, creds


__all__ = [
    "discover_resend_credentials",
    "enumerate_resend",
    "enum_resend_domains",
    "enum_resend_emails",
]
