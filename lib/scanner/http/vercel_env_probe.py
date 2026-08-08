#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Deep Vercel/Netlify environment leak detection on preview deploys."""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Tuple

from lib.scanner.http.preview_deploy_probe import (
    classify_deployment,
    extract_deploy_env_signals,
    has_env_mismatch,
    is_production_grade_secret,
)
from lib.scanner.http.vibe_secrets_probe import extract_vibe_secrets

_VERCEL_DEEP_PATHS = (
    "/",
    "/env.js",
    "/config.js",
    "/config/runtime-env.js",
    "/runtime-env.js",
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.preview",
    "/vercel.json",
    "/.vercel/project.json",
    "/_next/static/chunks/main.js",
    "/_next/static/chunks/pages/_app.js",
    "/api/_vercel/insights/script.js",
)

_VERCEL_ENV_PATTERNS = (
    (r"(?i)\bVERCEL_[A-Z0-9_]+\s*[=:]\s*['\"]([^'\"]{4,})['\"]", "vercel_env_var"),
    (r"(?i)\bNEXT_PUBLIC_[A-Z0-9_]+\s*[=:]\s*['\"]([^'\"]{8,})['\"]", "next_public_env"),
    (r'(?i)"VERCEL_GIT_COMMIT_REF"\s*:\s*"([^"]+)"', "vercel_git_ref"),
    (r'(?i)"VERCEL_URL"\s*:\s*"([^"]+)"', "vercel_url"),
    (r"(?i)\b(process\.env\.[A-Z0-9_]+)", "process_env_ref"),
)


def extract_vercel_env_leaks(text: str, source: str = "") -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    seen = set()
    for pattern, kind in _VERCEL_ENV_PATTERNS:
        for match in re.finditer(pattern, text or ""):
            val = match.group(1) if match.lastindex else match.group(0)
            key = f"{kind}:{val[:30]}"
            if key in seen:
                continue
            seen.add(key)
            if kind == "process_env_ref":
                findings.append({"kind": kind, "source": source, "name": val, "severity": "info"})
                continue
            if any(s in val.upper() for s in ("SECRET", "KEY", "TOKEN", "PASSWORD", "DATABASE")):
                sev = "critical"
            else:
                sev = "medium"
            findings.append(
                {
                    "kind": kind,
                    "source": source,
                    "value_preview": val[:80],
                    "severity": sev,
                }
            )
    return findings


def scan_vercel_env_leaks(
    http_request: Callable[..., Any],
    host: str = "",
    response_headers: Dict[str, str] | None = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    bodies: List[Tuple[str, str]] = []
    hdrs = dict(response_headers or {})

    for path in _VERCEL_DEEP_PATHS:
        response = http_request(method="GET", path=path, allow_redirects=path == "/")
        if not response or int(getattr(response, "status_code", 0) or 0) != 200:
            continue
        text = str(getattr(response, "text", "") or "")
        if not text.strip():
            continue
        bodies.append((path, text))
        if not hdrs and getattr(response, "headers", None):
            hdrs = dict(response.headers)

    homepage = next((t for p, t in bodies if p == "/"), "")
    deploy_info = classify_deployment(host, hdrs, homepage)
    env_signals = extract_deploy_env_signals(homepage)
    mismatch = has_env_mismatch(deploy_info, env_signals)

    secret_findings: List[Dict[str, Any]] = []
    for path, text in bodies:
        secret_findings.extend(extract_vibe_secrets(text[:800_000], source=path))
        findings.extend(extract_vercel_env_leaks(text, source=path))

    prod_secrets = [f for f in secret_findings if is_production_grade_secret(f)]
    if prod_secrets and deploy_info.get("deploy_type") in ("preview", "staging"):
        findings.append(
            {
                "kind": "prod_secrets_on_preview",
                "deploy_type": deploy_info.get("deploy_type"),
                "platform": deploy_info.get("platform"),
                "secret_count": len(prod_secrets),
                "services": sorted({str(f.get("service")) for f in prod_secrets}),
                "severity": "critical",
            }
        )
    if mismatch:
        findings.append(
            {
                "kind": "vercel_env_mismatch",
                "deploy_info": deploy_info,
                "severity": "high",
            }
        )
    for path, text in bodies:
        if path.endswith(".json") and ("env" in text.lower() or "secret" in text.lower()):
            findings.append(
                {
                    "kind": "vercel_config_env_exposed",
                    "path": path,
                    "preview": text[:300],
                    "severity": "high",
                }
            )

    return findings, deploy_info


__all__ = ["extract_vercel_env_leaks", "scan_vercel_env_leaks"]
