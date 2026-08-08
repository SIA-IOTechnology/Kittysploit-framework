#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Railway, Render, and Fly.io deploy classification + secret leak heuristics."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Mapping, Optional

_RAILWAY_SUFFIXES = (".up.railway.app", ".railway.app")
_RENDER_SUFFIXES = (".onrender.com",)
_FLY_SUFFIXES = (".fly.dev",)

_STAGING_RX = re.compile(
    r"(?i)^(staging|stage|dev|develop|preview|preprod|test|uat|qa|sandbox|canary|demo|pr-\d+)\."
)

_ENV_SIGNALS: tuple = (
    (re.compile(r'(?i)"RAILWAY_ENVIRONMENT"\s*:\s*"([^"]+)"'), "railway_env", "railway"),
    (re.compile(r"(?i)\bRAILWAY_ENVIRONMENT\s*=\s*['\"]?(production|staging|development)['\"]?"), "railway_env", "railway"),
    (re.compile(r'(?i)"RENDER(?:_SERVICE|_ENV)?"\s*:\s*"([^"]+)"'), "render_env", "render"),
    (re.compile(r"(?i)\bRENDER\s*=\s*['\"]?(true|production)['\"]?"), "render_env", "render"),
    (re.compile(r'(?i)"FLY_APP_NAME"\s*:\s*"([^"]+)"'), "fly_app", "fly"),
    (re.compile(r"(?i)\bFLY_REGION\s*=\s*['\"]?[a-z0-9-]+['\"]?"), "fly_region", "fly"),
)


def normalize_host(value: str) -> str:
    raw = (value or "").strip().lower()
    if "://" in raw:
        from urllib.parse import urlparse
        raw = urlparse(raw).hostname or raw
    return raw.split(":")[0].strip(".")


def classify_paas_deployment(
    host: str,
    headers: Optional[Mapping[str, str]] = None,
    body: str = "",
) -> Dict[str, Any]:
    hostname = normalize_host(host)
    hdrs = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    platform = "unknown"
    deploy_type = "unknown"
    signals: List[str] = []

    if any(hostname.endswith(s) for s in _RAILWAY_SUFFIXES):
        platform = "railway"
        signals.append("railway_hostname")
        deploy_type = "production"
    if any(hostname.endswith(s) for s in _RENDER_SUFFIXES):
        platform = "render"
        signals.append("render_hostname")
        if hostname.startswith("pr-") or "-pr-" in hostname:
            deploy_type = "preview"
            signals.append("render_pr_hostname")
        else:
            deploy_type = "production"
    if any(hostname.endswith(s) for s in _FLY_SUFFIXES):
        platform = "fly"
        signals.append("fly_hostname")
        deploy_type = "production"

    if _STAGING_RX.match(hostname):
        deploy_type = "staging"
        signals.append("staging_subdomain")

    for regex, key, plat in _ENV_SIGNALS:
        for match in regex.finditer(body or ""):
            val = match.group(1) if match.lastindex else "matched"
            signals.append(f"bundle:{key}={val}")
            platform = platform or plat
            if str(val).lower() in ("development", "staging", "preview"):
                deploy_type = "preview" if deploy_type == "unknown" else deploy_type

    if hdrs.get("x-railway-request-id"):
        platform = "railway"
        signals.append("header:x-railway-request-id")
    if hdrs.get("x-render-origin-server"):
        platform = "render"
        signals.append("header:x-render-origin-server")
    if hdrs.get("fly-request-id"):
        platform = "fly"
        signals.append("header:fly-request-id")

    return {
        "platform": platform,
        "deploy_type": deploy_type,
        "signals": signals,
        "hostname": hostname,
    }


__all__ = ["classify_paas_deployment", "normalize_host"]
