#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Helpers to reject SPA/HTML catch-all responses masquerading as product APIs."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Optional, Tuple


_HTML_MARKERS = (
    "<!doctype html",
    "<html",
    "<head",
    "<body",
    "<script",
    "<meta ",
)


def looks_like_html(text: str) -> bool:
    if not text:
        return False
    sample = str(text).lstrip()[:512].lower()
    return any(marker in sample for marker in _HTML_MARKERS)


def response_content_type(response) -> str:
    if not response or not getattr(response, "headers", None):
        return ""
    return str(response.headers.get("Content-Type") or "").lower()


def is_html_response(response, text: Optional[str] = None) -> bool:
    ctype = response_content_type(response)
    if "text/html" in ctype or "application/xhtml" in ctype:
        return True
    body = text if text is not None else str(getattr(response, "text", "") or "")
    return looks_like_html(body)


def parse_json_response(response) -> Tuple[Optional[Dict[str, Any]], str]:
    if not response or getattr(response, "status_code", 0) != 200:
        return None, "bad_status"
    body = str(getattr(response, "text", "") or "")
    if not body.strip():
        return None, "empty_body"
    if is_html_response(response, body):
        return None, "html_fallback"
    try:
        data = response.json()
    except Exception:
        try:
            data = json.loads(body)
        except Exception:
            return None, "invalid_json"
    if not isinstance(data, dict):
        return None, "not_object"
    return data, ""


def is_xml_response(text: str) -> bool:
    if not text or looks_like_html(text):
        return False
    sample = str(text).lstrip()[:256].lower()
    return sample.startswith("<?xml") or "<extension" in sample or "<metafile" in sample


def looks_like_kubernetes_version(data: Dict[str, Any]) -> bool:
    if not isinstance(data, dict):
        return False
    if "gitVersion" not in data:
        return False
    return "major" in data or "minor" in data


def looks_like_kubernetes_resource_list(data: Dict[str, Any]) -> bool:
    if not isinstance(data, dict):
        return False
    kind = str(data.get("kind") or "")
    if not kind.endswith("List"):
        return False
    if not str(data.get("apiVersion") or "").startswith(("v1", "apps/", "batch/")):
        return False
    return isinstance(data.get("items"), list)


def looks_like_kubernetes_health(text: str, response) -> bool:
    if is_html_response(response, text):
        return False
    body = str(text or "").strip().lower()
    if body not in ("ok", "success"):
        return False
    ctype = response_content_type(response)
    return not ctype or "text/plain" in ctype or "text/html" not in ctype


def looks_like_spring_actuator_links(data: Dict[str, Any]) -> bool:
    links = (data or {}).get("_links") if isinstance(data, dict) else None
    return isinstance(links, dict) and bool(links)


def looks_like_spring_actuator_health(data: Dict[str, Any]) -> bool:
    if not isinstance(data, dict) or "status" not in data:
        return False
    return str(data.get("status") or "").upper() in (
        "UP",
        "DOWN",
        "OUT_OF_SERVICE",
        "UNKNOWN",
    )


def looks_like_spring_actuator_env(data: Dict[str, Any]) -> bool:
    return isinstance(data, dict) and isinstance(data.get("propertySources"), list)


def looks_like_vercel_source_exposure(body: str) -> bool:
    text = str(body or "")
    if not text:
        return False
    login_markers = (
        "<title>Login – Vercel</title>",
        "<title>Login - Vercel</title>",
        'data-testid="login',
        "/login?next=",
        "Sign in to Vercel",
    )
    if any(marker in text for marker in login_markers):
        return False
    exposure_markers = (
        "Deployment Source</title>",
        "Deployment Source – Dashboard – Vercel",
        "Deployment Source - Dashboard - Vercel",
    )
    if not any(marker in text for marker in exposure_markers):
        return False
    source_indicators = (
        "Source Files",
        "Browse Source",
        "view-source",
        'data-testid="source',
        "/_src/",
        ".tsx",
        ".jsx",
        "package.json",
    )
    return any(marker in text for marker in source_indicators)


def get_header_value(response, header_name: str) -> str:
    if not response or not getattr(response, "headers", None):
        return ""
    headers = response.headers
    for key, value in headers.items():
        if str(key).lower() == header_name.lower():
            return str(value or "")
    return ""


def csp_header_value(response) -> str:
    return get_header_value(response, "Content-Security-Policy")


_WEAK_CSP_MARKERS = (
    "'unsafe-inline'",
    "'unsafe-eval'",
    " *;",
    " * ",
    " data:",
    "blob:",
)


def is_weak_csp(policy: str) -> bool:
    value = str(policy or "").strip()
    if not value:
        return False
    low = value.lower()
    if "script-src" not in low and "default-src" not in low:
        return False
    return any(marker in low for marker in _WEAK_CSP_MARKERS)
