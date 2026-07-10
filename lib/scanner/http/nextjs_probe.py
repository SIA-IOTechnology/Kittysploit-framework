#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Shared Next.js stack fingerprinting for HTTP scanner modules."""

from __future__ import annotations

import re
from typing import Any, List, Optional, Tuple

from lib.scanner.http.detectors import detect_wordpress, evidence_nextjs, is_nextjs, php_stack_likely

_NEXT_VERSION_PATTERNS = (
    re.compile(r"next\.js[/\s]+v?([\d.]+)", re.I),
    re.compile(r'"nextVersion"\s*:\s*"([\d.]+)"', re.I),
    re.compile(r"x-powered-by:\s*next\.js\s*([\d.]+)", re.I),
)


def probe_nextjs_stack(module: Any) -> Tuple[bool, str]:
    """
    GET the module homepage and decide if Next.js-specific probes should run.

    Returns:
        (True, "") when the target looks like Next.js
        (False, reason) when probes should be skipped (e.g. WordPress/PHP site)
    """
    try:
        if hasattr(module, "http_request"):
            response = module.http_request(method="GET", path="/", allow_redirects=True)
        else:
            return False, "http client unavailable"
    except Exception as exc:
        return False, f"baseline unreachable: {exc}"

    if not response:
        return False, "baseline empty response"
    if is_nextjs(response):
        return True, ""
    if detect_wordpress(response):
        return False, "WordPress detected (not Next.js)"
    if php_stack_likely(response):
        return False, "PHP stack detected (not Next.js)"
    label = evidence_nextjs(response)
    if label:
        return True, ""
    return False, "no Next.js fingerprint"


def ensure_nextjs_target(module: Any) -> bool:
    """Skip module early when the target is not Next.js; sets scan info when skipped."""
    ok, reason = probe_nextjs_stack(module)
    if ok:
        return True
    if hasattr(module, "set_info"):
        module.set_info(reason=reason, confidence="low")
    return False


def extract_nextjs_version(response: Any) -> str:
    """Best-effort Next.js version from headers or HTML."""
    if not response:
        return ""
    chunks: List[str] = []
    if hasattr(response, "headers"):
        chunks.append(str(response.headers.get("X-Powered-By") or ""))
    chunks.append(getattr(response, "text", None) or "")
    blob = "\n".join(chunks)
    for pattern in _NEXT_VERSION_PATTERNS:
        match = pattern.search(blob)
        if match:
            return match.group(1).strip()
    return ""


def nextjs_version_tuple(version: str) -> Tuple[int, ...]:
    parts: List[int] = []
    for token in str(version or "").split("."):
        digits = "".join(ch for ch in token if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:4])


def nextjs_version_lt(version: str, limit: str) -> bool:
    left = list(nextjs_version_tuple(version))
    right = list(nextjs_version_tuple(limit))
    width = max(len(left), len(right))
    left.extend([0] * (width - len(left)))
    right.extend([0] * (width - len(right)))
    return tuple(left) < tuple(right)


def run_nextjs_version_scan(
    module: Any,
    *,
    patched_version: str = "16.2.5",
    cve: str = "",
    advisory: str = "",
    issue_label: str = "",
    severity: str = "high",
    modules: Optional[List[str]] = None,
) -> bool:
    """
    Simple Next.js scanner: fingerprint stack, compare version to patched threshold.
    Active exploitation belongs in auxiliary/exploit modules.
    """
    ok, reason = probe_nextjs_stack(module)
    if not ok:
        if hasattr(module, "set_info"):
            module.set_info(reason=reason, confidence="low")
        return False

    response = None
    try:
        response = module.http_request(method="GET", path="/", allow_redirects=True)
    except Exception as exc:
        if hasattr(module, "set_info"):
            module.set_info(reason=f"baseline unreachable: {exc}", confidence="low")
        return False

    version = extract_nextjs_version(response)
    label = issue_label or cve or advisory or "Next.js advisory"
    id_key = cve or advisory

    if version:
        if nextjs_version_lt(version, patched_version):
            if hasattr(module, "set_info"):
                module.set_info(
                    severity=severity,
                    cve=id_key or None,
                    reason=(
                        f"Next.js {version} detected; < {patched_version} may be affected by {label}"
                    ),
                    version=version,
                    confidence="high",
                )
            return True
        if hasattr(module, "set_info"):
            module.set_info(
                severity="info",
                reason=(
                    f"Next.js {version} detected; >= {patched_version} appears patched for {label}"
                ),
                version=version,
            )
        return False

    if hasattr(module, "set_info"):
        module.set_info(
            severity="medium",
            cve=id_key or None,
            reason=(
                f"Next.js detected but version unknown; may be affected by {label} if < {patched_version}"
            ),
            confidence="low",
        )
    return True
