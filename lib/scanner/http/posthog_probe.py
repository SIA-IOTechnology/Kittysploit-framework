#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PostHog analytics key discovery and PII/event enumeration."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from lib.scanner.http.vibe_secrets_probe import mask_secret

_POSTHOG_KEY_RE = re.compile(r"\b(phc_[A-Za-z0-9]{20,}|phx_[A-Za-z0-9]{20,})\b")
_HOST_RE = re.compile(
    r"(?i)(?:posthog\.init\s*\(\s*['\"][^'\"]+['\"]\s*,\s*\{[^}]*api_host\s*:\s*['\"]([^'\"]+)['\"]|"
    r"NEXT_PUBLIC_POSTHOG_(?:HOST|KEY)[^'\"]*['\"]([^'\"]+)['\"])",
)


def discover_posthog_credentials(text: str) -> Dict[str, str]:
    creds: Dict[str, str] = {}
    body = text or ""
    for match in _POSTHOG_KEY_RE.finditer(body):
        key = match.group(1)
        if key.startswith("phx_"):
            creds["personal_api_key"] = key
        else:
            creds.setdefault("project_api_key", key)
    for match in re.finditer(
        r"(?i)(?:POSTHOG_(?:PERSONAL|PROJECT|API)_KEY|NEXT_PUBLIC_POSTHOG_KEY)\s*[=:]\s*['\"]([^'\"]+)['\"]",
        body,
    ):
        val = match.group(1).strip()
        if val.startswith("phx_"):
            creds["personal_api_key"] = val
        elif val.startswith("phc_"):
            creds["project_api_key"] = val
    for match in _HOST_RE.finditer(body):
        host = (match.group(1) or match.group(2) or "").strip().rstrip("/")
        if host.startswith("http"):
            creds["api_host"] = host
    if "api_host" not in creds:
        if "eu.posthog.com" in body:
            creds["api_host"] = "https://eu.posthog.com"
        elif "posthog.com" in body.lower():
            creds["api_host"] = "https://us.posthog.com"
    return creds


def _base(api_host: str) -> str:
    host = (api_host or "https://us.posthog.com").rstrip("/")
    if not host.startswith("http"):
        host = f"https://{host}"
    return host


def enum_posthog_projects(
    session,
    personal_key: str,
    api_host: str = "",
    *,
    verify_ssl: bool = True,
) -> Dict[str, Any]:
    url = f"{_base(api_host)}/api/projects/"
    headers = {"Authorization": f"Bearer {personal_key}", "Accept": "application/json"}
    try:
        response = session.get(url, headers=headers, timeout=12, verify=verify_ssl)
    except Exception as exc:
        return {"platform": "posthog", "ok": False, "detail": str(exc)}
    if response.status_code == 401:
        return {"platform": "posthog", "ok": False, "detail": "key_rejected"}
    if response.status_code != 200:
        return {"platform": "posthog", "ok": False, "detail": f"http_{response.status_code}"}
    try:
        data = response.json()
    except Exception:
        return {"platform": "posthog", "ok": False, "detail": "invalid_json"}
    projects = data.get("results") if isinstance(data, dict) else data
    names = [str(p.get("name") or p.get("id") or "") for p in (projects or [])[:5] if isinstance(p, dict)]
    return {
        "platform": "posthog",
        "ok": True,
        "kind": "projects_listed",
        "projects": names,
        "count": len(projects or []),
        "severity": "critical",
    }


def enum_posthog_events(
    session,
    project_id: str,
    personal_key: str,
    api_host: str = "",
    *,
    verify_ssl: bool = True,
) -> Dict[str, Any]:
    url = f"{_base(api_host)}/api/projects/{project_id}/events/"
    headers = {"Authorization": f"Bearer {personal_key}", "Accept": "application/json"}
    try:
        response = session.get(url, headers=headers, params={"limit": 5}, timeout=12, verify=verify_ssl)
    except Exception as exc:
        return {"platform": "posthog", "ok": False, "detail": str(exc)}
    if response.status_code != 200:
        return {"platform": "posthog", "ok": False, "detail": f"http_{response.status_code}"}
    try:
        data = response.json()
    except Exception:
        return {"platform": "posthog", "ok": False, "detail": "invalid_json"}
    events = data.get("results") if isinstance(data, dict) else []
    samples = []
    for ev in (events or [])[:5]:
        if not isinstance(ev, dict):
            continue
        props = ev.get("properties") or {}
        samples.append(
            {
                "event": str(ev.get("event") or ""),
                "distinct_id": str(ev.get("distinct_id") or props.get("distinct_id") or "")[:40],
                "email_hint": str(props.get("email") or props.get("$email") or "")[:60],
            }
        )
    return {
        "platform": "posthog",
        "ok": True,
        "kind": "events_with_pii",
        "event_samples": samples,
        "severity": "critical" if any(s.get("email_hint") for s in samples) else "high",
    }


def enumerate_posthog(
    session,
    homepage_html: str,
    *,
    verify_ssl: bool = True,
    personal_key: str = "",
    project_key: str = "",
    api_host: str = "",
) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
    creds = discover_posthog_credentials(homepage_html or "")
    if personal_key:
        creds["personal_api_key"] = personal_key
    if project_key:
        creds["project_api_key"] = project_key
    if api_host:
        creds["api_host"] = api_host

    findings: List[Dict[str, Any]] = []
    phx = creds.get("personal_api_key") or ""
    host = creds.get("api_host") or ""
    if phx:
        proj_hit = enum_posthog_projects(session, phx, host, verify_ssl=verify_ssl)
        proj_hit["key_masked"] = mask_secret(phx)
        findings.append(proj_hit)
        if proj_hit.get("ok") and proj_hit.get("count", 0) > 0:
            # Try project id 1 or fetch from projects endpoint again for id
            try:
                url = f"{_base(host)}/api/projects/"
                resp = session.get(
                    url,
                    headers={"Authorization": f"Bearer {phx}"},
                    timeout=12,
                    verify=verify_ssl,
                )
                data = resp.json()
                results = data.get("results") or []
                if results and isinstance(results[0], dict):
                    pid = str(results[0].get("id") or "")
                    if pid:
                        findings.append(
                            enum_posthog_events(session, pid, phx, host, verify_ssl=verify_ssl)
                        )
            except Exception:
                pass
    elif creds.get("project_api_key"):
        findings.append(
            {
                "platform": "posthog",
                "ok": False,
                "detail": "project_key_only_no_personal_api_key",
                "key_masked": mask_secret(creds["project_api_key"]),
                "severity": "medium",
            }
        )
    return findings, creds


__all__ = [
    "discover_posthog_credentials",
    "enumerate_posthog",
    "enum_posthog_projects",
    "enum_posthog_events",
]
