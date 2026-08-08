#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Cloudflare Workers/Pages config leaks (wrangler, env vars)."""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Tuple

_CF_PATHS = (
    "/wrangler.toml",
    "/wrangler.json",
    "/wrangler.jsonc",
    "/.dev.vars",
    "/.env.production",
    "/workers-site/wrangler.toml",
)

_SECRET_RULES: Tuple[Tuple[str, str, str], ...] = (
    (r"(?i)\b(CLOUDFLARE_API_TOKEN|CF_API_TOKEN|CF_ACCOUNT_ID)\s*=\s*['\"]?([^\s'\"#]+)", "cloudflare_token", "critical"),
    (r"(?i)\b(API_TOKEN|ACCOUNT_ID)\s*=\s*['\"]?([^\s'\"#]{16,})", "wrangler_credential", "high"),
    (r"(?i)vars\s*=\s*\{[^}]*(SECRET|TOKEN|PASSWORD|API_KEY)", "wrangler_vars_secret", "high"),
    (r"(?i)\[vars\][^\[]*(SECRET|TOKEN|PASSWORD|API_KEY)\s*=\s*['\"]?([^\s'\"#]+)", "toml_var_secret", "critical"),
    (r"(?i)compatibility_date\s*=", "wrangler_config", "info"),
    (r"(?i)main\s*=\s*['\"]?[^'\"]+\.js['\"]?", "worker_entrypoint", "info"),
)

_COMPILED = [(re.compile(rx), kind, sev) for rx, kind, sev in _SECRET_RULES]


def scan_cloudflare_config(path: str, text: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    seen = set()
    for regex, kind, severity in _COMPILED:
        for match in regex.finditer(text or ""):
            sig = (path, kind, match.group(0)[:60])
            if sig in seen:
                continue
            seen.add(sig)
            findings.append(
                {
                    "path": path,
                    "kind": kind,
                    "severity": severity,
                    "match": match.group(0)[:200],
                }
            )
    return findings


def collect_cloudflare_config_bodies(
    http_request: Callable[..., Any],
) -> List[Tuple[str, str]]:
    bodies: List[Tuple[str, str]] = []
    for path in _CF_PATHS:
        response = http_request(method="GET", path=path, allow_redirects=False)
        if not response or int(getattr(response, "status_code", 0) or 0) != 200:
            continue
        text = str(getattr(response, "text", "") or "")
        if text.strip():
            bodies.append((path, text))
    return bodies


def extract_cloudflare_workers_findings(
    http_request: Callable[..., Any],
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for path, text in collect_cloudflare_config_bodies(http_request):
        out.extend(scan_cloudflare_config(path, text))
    return out


__all__ = [
    "collect_cloudflare_config_bodies",
    "extract_cloudflare_workers_findings",
    "scan_cloudflare_config",
]
