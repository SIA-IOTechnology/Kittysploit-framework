#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tribulant Newsletters WordPress plugin helpers."""

from __future__ import annotations

import re
from typing import Optional, Tuple

from core.framework.base_module import BaseModule


class Tribulant_newsletters(BaseModule):
    """Fingerprint and safe deserialization probe indicators."""

    README_PATHS = (
        "/wp-content/plugins/newsletters-lite/readme.txt",
        "/wp-content/plugins/newsletters/readme.txt",
    )

    @staticmethod
    def newsletters_match(text: str) -> bool:
        blob = (text or "").lower()
        return "tribulant" in blob or "newsletters" in blob

    def newsletters_detected(self) -> Tuple[bool, str]:
        for path in self.README_PATHS:
            resp = self.http_request("GET", path, timeout=12)
            if resp and self.newsletters_match(resp.text or ""):
                version = ""
                match = re.search(r"Stable tag:\s*([\w.\-]+)", resp.text or "", re.I)
                if match:
                    version = match.group(1)
                return True, version
        resp = self.http_request("GET", "/", timeout=12)
        if resp and self.newsletters_match(resp.text or ""):
            return True, ""
        return False, ""

    def newsletters_deser_probe(
        self,
        payload: str,
        param: str = "data",
    ) -> Optional[dict]:
        data = {"action": "newsletters", param: payload}
        indicators = ("unserialize", "__wakeup", "__destruct", "object of class")
        for ep in ("/wp-admin/admin-ajax.php", "/wp-admin/admin-post.php"):
            resp = self.http_request("POST", ep, data=data, timeout=25)
            if not resp:
                continue
            text = (resp.text or "").lower()
            code = int(resp.status_code or 0)
            if code >= 500 or any(ind in text for ind in indicators):
                return {"endpoint": ep, "status_code": code}
        return None