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
