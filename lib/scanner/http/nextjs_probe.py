#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Shared Next.js stack fingerprinting for HTTP scanner modules."""

from __future__ import annotations

from typing import Any, Tuple

from lib.scanner.http.detectors import detect_wordpress, evidence_nextjs, is_nextjs, php_stack_likely


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
