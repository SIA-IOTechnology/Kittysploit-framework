#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""LangSmith and Langfuse API key abuse probes."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

from lib.scanner.http.vibe_secrets_probe import mask_secret

_LANGSMITH_RE = re.compile(r"\blsv2_(pt|sk)_[A-Za-z0-9_-]{20,}\b")
_LANGFUSE_RE = re.compile(r"\blf_(pk|sk)_[A-Za-z0-9_-]{20,}\b")


def discover_llm_observability_keys(text: str) -> Dict[str, str]:
    creds: Dict[str, str] = {}
    body = text or ""
    for match in _LANGSMITH_RE.finditer(body):
        creds["langsmith_api_key"] = match.group(0)
    for match in _LANGFUSE_RE.finditer(body):
        key = match.group(0)
        if key.startswith("lf_sk_"):
            creds["langfuse_secret_key"] = key
        else:
            creds.setdefault("langfuse_public_key", key)
    for match in re.finditer(
        r"(?i)(LANGSMITH_API_KEY|LANGCHAIN_API_KEY)\s*[=:]\s*['\"]([^'\"]+)['\"]",
        body,
    ):
        creds["langsmith_api_key"] = match.group(2).strip()
    for match in re.finditer(
        r"(?i)LANGFUSE_(?:SECRET|PUBLIC)_KEY\s*[=:]\s*['\"]([^'\"]+)['\"]",
        body,
    ):
        val = match.group(1).strip()
        if val.startswith("lf_sk_"):
            creds["langfuse_secret_key"] = val
        else:
            creds["langfuse_public_key"] = val
    for match in re.finditer(
        r"(?i)LANGFUSE_(?:BASEURL|HOST)\s*[=:]\s*['\"]([^'\"]+)['\"]",
        body,
    ):
        creds["langfuse_host"] = match.group(1).strip().rstrip("/")
    return creds


def enum_langsmith(session, api_key: str, *, verify_ssl: bool = True) -> Dict[str, Any]:
    headers = {"x-api-key": api_key, "Accept": "application/json"}
    for url in (
        "https://api.smith.langchain.com/sessions",
        "https://api.smith.langchain.com/runs/query",
    ):
        try:
            response = session.get(url, headers=headers, params={"limit": 3}, timeout=12, verify=verify_ssl)
        except Exception as exc:
            return {"platform": "langsmith", "ok": False, "detail": str(exc)}
        if response.status_code == 401:
            return {"platform": "langsmith", "ok": False, "detail": "key_rejected"}
        if response.status_code == 200:
            try:
                data = response.json()
            except Exception:
                data = response.text[:200]
            return {
                "platform": "langsmith",
                "ok": True,
                "endpoint": url,
                "preview": str(data)[:400],
                "severity": "critical",
            }
    return {"platform": "langsmith", "ok": False, "detail": "no_accessible_endpoint"}


def enum_langfuse(
    session,
    public_key: str,
    secret_key: str,
    host: str = "",
    *,
    verify_ssl: bool = True,
) -> Dict[str, Any]:
    base = (host or "https://cloud.langfuse.com").rstrip("/")
    if not base.startswith("http"):
        base = f"https://{base}"
    import base64

    auth = base64.b64encode(f"{public_key}:{secret_key}".encode()).decode()
    headers = {"Authorization": f"Basic {auth}", "Accept": "application/json"}
    url = f"{base}/api/public/traces"
    try:
        response = session.get(url, headers=headers, params={"limit": 3}, timeout=12, verify=verify_ssl)
    except Exception as exc:
        return {"platform": "langfuse", "ok": False, "detail": str(exc)}
    if response.status_code == 401:
        return {"platform": "langfuse", "ok": False, "detail": "key_rejected"}
    if response.status_code != 200:
        return {"platform": "langfuse", "ok": False, "detail": f"http_{response.status_code}"}
    try:
        data = response.json()
    except Exception:
        data = {}
    traces = data.get("data") if isinstance(data, dict) else []
    return {
        "platform": "langfuse",
        "ok": True,
        "endpoint": url,
        "trace_count": len(traces or []),
        "severity": "critical",
    }


def enumerate_llm_observability(
    session,
    homepage_html: str,
    *,
    verify_ssl: bool = True,
    langsmith_key: str = "",
    langfuse_public: str = "",
    langfuse_secret: str = "",
    langfuse_host: str = "",
) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
    creds = discover_llm_observability_keys(homepage_html or "")
    if langsmith_key:
        creds["langsmith_api_key"] = langsmith_key
    if langfuse_public:
        creds["langfuse_public_key"] = langfuse_public
    if langfuse_secret:
        creds["langfuse_secret_key"] = langfuse_secret
    if langfuse_host:
        creds["langfuse_host"] = langfuse_host

    findings: List[Dict[str, Any]] = []
    ls = creds.get("langsmith_api_key") or ""
    if ls:
        hit = enum_langsmith(session, ls, verify_ssl=verify_ssl)
        hit["key_masked"] = mask_secret(ls)
        findings.append(hit)

    lf_pub = creds.get("langfuse_public_key") or ""
    lf_sec = creds.get("langfuse_secret_key") or ""
    if lf_pub and lf_sec:
        hit = enum_langfuse(session, lf_pub, lf_sec, creds.get("langfuse_host", ""), verify_ssl=verify_ssl)
        findings.append(hit)
    elif lf_sec or lf_pub:
        findings.append(
            {
                "platform": "langfuse",
                "ok": False,
                "detail": "incomplete_langfuse_key_pair",
                "severity": "medium",
            }
        )
    return findings, creds


__all__ = [
    "discover_llm_observability_keys",
    "enumerate_llm_observability",
    "enum_langsmith",
    "enum_langfuse",
]
