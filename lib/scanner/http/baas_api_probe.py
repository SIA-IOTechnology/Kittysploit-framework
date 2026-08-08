#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Enumerate Convex, Appwrite, and PocketBase APIs using leaked or discovered credentials."""

from __future__ import annotations

import json
import re
from typing import Any, Callable, Dict, List, Tuple

from lib.scanner.http.vibe_secrets_probe import extract_vibe_secrets


def discover_baas_credentials(text: str) -> Dict[str, str]:
    creds: Dict[str, str] = {}
    for finding in extract_vibe_secrets(text[:500_000], source="/"):
        service = str(finding.get("service") or "")
        var_name = str(finding.get("var_name") or "").upper()
        value = str(finding.get("value") or "")
        if service == "convex" and finding.get("kind") == "secret_key" and value:
            creds.setdefault("convex_key", value)
        if "APPWRITE" in var_name and value:
            if value.startswith("http"):
                creds.setdefault("appwrite_endpoint", value.rstrip("/"))
            elif "PROJECT" in var_name:
                creds.setdefault("appwrite_project", value)
    for match in re.finditer(r"https://([a-z0-9-]+)\.convex\.cloud", text or "", re.I):
        creds.setdefault("convex_deployment", match.group(1))
    for match in re.finditer(
        r"(?i)(?:NEXT_PUBLIC_|VITE_|REACT_APP_)?APPWRITE_(?:ENDPOINT|URL)[^=]*=\s*['\"]([^'\"]+)['\"]",
        text or "",
    ):
        creds.setdefault("appwrite_endpoint", match.group(1).rstrip("/"))
    for match in re.finditer(
        r"(?i)(?:NEXT_PUBLIC_|VITE_|REACT_APP_)?APPWRITE_PROJECT[^=]*=\s*['\"]([^'\"]+)['\"]",
        text or "",
    ):
        creds.setdefault("appwrite_project", match.group(1))
    return creds


def enum_pocketbase(http_request: Callable[..., Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for path in ("/api/health", "/api/collections", "/api/settings"):
        response = http_request(method="GET", path=path, allow_redirects=False, timeout=10)
        if not response:
            continue
        status = int(getattr(response, "status_code", 0) or 0)
        body = str(getattr(response, "text", "") or "")
        if path == "/api/health" and status == 200 and "message" in body:
            findings.append({"platform": "pocketbase", "path": path, "kind": "health_exposed", "preview": body[:300]})
        if path == "/api/collections" and status == 200:
            try:
                data = json.loads(body)
                items = data if isinstance(data, list) else data.get("items") or []
                names = [str(i.get("name") or "") for i in items if isinstance(i, dict)][:20]
                findings.append(
                    {
                        "platform": "pocketbase",
                        "path": path,
                        "kind": "collections_listed",
                        "collections": names,
                        "count": len(names),
                        "severity": "high",
                    }
                )
            except Exception:
                findings.append({"platform": "pocketbase", "path": path, "kind": "collections_raw", "preview": body[:300]})
    return findings


def enum_appwrite(
    http_request: Callable[..., Any],
    project_id: str = "",
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    headers = {"X-Appwrite-Project": project_id} if project_id else {}
    for path_suffix in ("/v1/health", "/v1/databases", "/v1/storage/buckets"):
        response = http_request(method="GET", path=path_suffix, headers=headers, allow_redirects=False, timeout=10)
        if not response:
            continue
        status = int(getattr(response, "status_code", 0) or 0)
        body = str(getattr(response, "text", "") or "")
        if status == 200:
            findings.append(
                {
                    "platform": "appwrite",
                    "path": path_suffix,
                    "kind": "api_enum",
                    "status": status,
                    "preview": body[:400],
                    "severity": "high",
                }
            )
        elif status == 401 and "project" in body.lower():
            findings.append(
                {
                    "platform": "appwrite",
                    "path": path_suffix,
                    "kind": "appwrite_reachable_auth_required",
                    "status": status,
                    "severity": "medium",
                }
            )
    return findings


def enum_convex_from_bundle(deployment: str) -> List[Dict[str, Any]]:
    if not deployment:
        return []
    return [
        {
            "platform": "convex",
            "deployment": deployment,
            "kind": "convex_deployment_discovered",
            "url": f"https://{deployment}.convex.cloud",
            "severity": "medium",
            "note": "Run auxiliary enum with CONVEX_DEPLOYMENT against convex.cloud if deploy key leaked",
        }
    ]


def enumerate_baas_targets(
    http_request: Callable[..., Any],
    homepage_html: str = "",
) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
    creds = discover_baas_credentials(homepage_html or "")
    findings: List[Dict[str, Any]] = []
    findings.extend(enum_pocketbase(http_request))
    findings.extend(enum_appwrite(http_request, creds.get("appwrite_project", "")))
    if creds.get("convex_deployment"):
        findings.extend(enum_convex_from_bundle(creds["convex_deployment"]))
    return findings, creds


__all__ = [
    "discover_baas_credentials",
    "enumerate_baas_targets",
    "enum_appwrite",
    "enum_convex_from_bundle",
    "enum_pocketbase",
]
