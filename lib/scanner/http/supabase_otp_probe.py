#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Supabase Auth OTP and magic link abuse probes."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

from lib.scanner.http.supabase_probe import (
    extract_supabase_findings,
    mask_token,
    supabase_base_url,
    supabase_headers,
)

_PROBE_EMAIL = "security-probe@example.com"


def discover_supabase_auth_credentials(text: str) -> Dict[str, str]:
    creds: Dict[str, str] = {}
    for finding in extract_supabase_findings(text or "", source="/"):
        ref = str(finding.get("project_ref") or "")
        token = str(finding.get("token") or "")
        role = str(finding.get("role") or "")
        if ref and not creds.get("project_ref"):
            creds["project_ref"] = ref
        if token and role in ("anon", "unknown", "info"):
            creds.setdefault("anon_key", token)
        if token and role == "service_role":
            creds["service_role_key"] = token
    return creds


def probe_supabase_otp(
    session,
    project_ref: str,
    api_key: str,
    email: str = _PROBE_EMAIL,
    *,
    verify_ssl: bool = True,
) -> Dict[str, Any]:
    url = f"{supabase_base_url(project_ref)}/auth/v1/otp"
    headers = dict(supabase_headers(api_key))
    headers["Content-Type"] = "application/json"
    payload = {"email": email, "create_user": False}
    try:
        response = session.post(url, headers=headers, json=payload, timeout=12, verify=verify_ssl)
    except Exception as exc:
        return {"platform": "supabase", "ok": False, "detail": str(exc)}
    status = int(getattr(response, "status_code", 0) or 0)
    text = str(getattr(response, "text", "") or "")
    if status in (200, 201):
        return {
            "platform": "supabase",
            "ok": True,
            "kind": "otp_send_accepted",
            "status_code": status,
            "email": email,
            "preview": text[:300],
            "severity": "high",
        }
    if status == 400 and "email" in text.lower():
        return {
            "platform": "supabase",
            "ok": True,
            "kind": "otp_endpoint_active",
            "status_code": status,
            "preview": text[:300],
            "severity": "medium",
        }
    if status == 429:
        return {
            "platform": "supabase",
            "ok": True,
            "kind": "otp_rate_limited",
            "status_code": status,
            "severity": "info",
        }
    return {"platform": "supabase", "ok": False, "detail": f"http_{status}", "preview": text[:200]}


def probe_supabase_magic_link(
    session,
    project_ref: str,
    api_key: str,
    email: str = _PROBE_EMAIL,
    *,
    verify_ssl: bool = True,
) -> Dict[str, Any]:
    url = f"{supabase_base_url(project_ref)}/auth/v1/magiclink"
    headers = dict(supabase_headers(api_key))
    headers["Content-Type"] = "application/json"
    payload = {"email": email}
    try:
        response = session.post(url, headers=headers, json=payload, timeout=12, verify=verify_ssl)
    except Exception as exc:
        return {"platform": "supabase", "ok": False, "detail": str(exc)}
    status = int(getattr(response, "status_code", 0) or 0)
    text = str(getattr(response, "text", "") or "")
    if status in (200, 201):
        return {
            "platform": "supabase",
            "ok": True,
            "kind": "magiclink_send_accepted",
            "status_code": status,
            "severity": "high",
            "preview": text[:300],
        }
    return {"platform": "supabase", "ok": False, "detail": f"http_{status}"}


def enumerate_supabase_otp(
    session,
    homepage_html: str,
    *,
    verify_ssl: bool = True,
    project_ref: str = "",
    anon_key: str = "",
    email: str = _PROBE_EMAIL,
) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
    creds = discover_supabase_auth_credentials(homepage_html or "")
    if project_ref:
        creds["project_ref"] = project_ref
    if anon_key:
        creds["anon_key"] = anon_key

    findings: List[Dict[str, Any]] = []
    ref = creds.get("project_ref") or ""
    key = creds.get("anon_key") or ""
    if not ref or not key:
        return findings, creds

    otp = probe_supabase_otp(session, ref, key, email, verify_ssl=verify_ssl)
    if otp.get("ok"):
        otp["key_masked"] = mask_token(key)
        findings.append(otp)
    magic = probe_supabase_magic_link(session, ref, key, email, verify_ssl=verify_ssl)
    if magic.get("ok"):
        magic["key_masked"] = mask_token(key)
        findings.append(magic)
    return findings, creds


__all__ = [
    "discover_supabase_auth_credentials",
    "enumerate_supabase_otp",
    "probe_supabase_magic_link",
    "probe_supabase_otp",
]
