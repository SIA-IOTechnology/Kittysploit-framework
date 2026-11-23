#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unstable Slope Management Program HTTP helpers."""

from __future__ import annotations

from typing import Optional

from core.framework.base_module import BaseModule


class Slope_management(BaseModule):
    """Missing authentication on critical paths."""

    def slope_reachable(self) -> bool:
        resp = self.http_request("GET", "/", timeout=12)
        return bool(resp and int(resp.status_code or 0) < 500)

    def slope_unauth_access(self, path: str) -> Optional[dict]:
        resp = self.http_request("GET", path, allow_redirects=False, timeout=15)
        if not resp:
            return None
        code = int(resp.status_code or 0)
        text = (resp.text or "")[:500].lower()
        if code == 200 and "login" not in text:
            return {
                "path": path,
                "status_code": code,
                "length": len(resp.content or b""),
            }
        return None