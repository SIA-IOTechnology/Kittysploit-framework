#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Mang Board WordPress plugin helpers."""

from __future__ import annotations

import re
from typing import Optional, Tuple

from core.framework.base_module import BaseModule


class Mangboard(BaseModule):
    """Mang Board fingerprint and admin-ajax probe."""

    @staticmethod
    def mangboard_body_match(text: str) -> bool:
        blob = (text or "").lower()
        return "mangboard" in blob or "mang board" in blob

    def mangboard_detected(self) -> Tuple[bool, str]:
        for path in ("/", "/wp-content/plugins/mangboard/readme.txt"):
            resp = self.http_request("GET", path, timeout=12)
            if resp and self.mangboard_body_match(resp.text or ""):
                version = ""
                if "readme" in path:
                    match = re.search(r"Stable tag:\s*([\w.\-]+)", resp.text or "", re.I)
                    if match:
                        version = match.group(1)
                return True, version
        return False, ""

    def mangboard_invoke(self, action: str) -> Tuple[int, str, bool]:
        resp = self.http_request(
            "POST",
            "/wp-admin/admin-ajax.php",
            data={"action": action},
            timeout=20,
        )
        if not resp:
            return 0, "", False
        body = (resp.text or "").strip()
        code = int(resp.status_code or 0)
        low = body.lower()
        ok = (
            code == 200
            and body not in ("-1", "0")
            and "permission" not in low
            and "denied" not in low
        )
        return code, body[:500], ok