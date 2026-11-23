#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Etherpad HTTP fingerprint helpers."""

from __future__ import annotations

from typing import Any, Dict, Optional

from core.framework.base_module import BaseModule


class Etherpad(BaseModule):
    def etherpad_fingerprint(self) -> Dict[str, Any]:
        resp = self.http_request(method="GET", path="/")
        if not resp:
            return {"reachable": False, "is_etherpad": False}
        headers = {k.lower(): v for k, v in (resp.headers or {}).items()}
        body = (resp.text or "").lower()
        is_ep = (
            "etherpad" in body
            or "pad.js" in body
            or "etherpad" in headers.get("x-generator", "").lower()
        )
        return {
            "reachable": int(resp.status_code or 0) < 500,
            "is_etherpad": is_ep,
            "status": int(resp.status_code or 0),
        }

    def etherpad_read_path(self, api_path: str) -> Optional[Any]:
        path = api_path if str(api_path).startswith("/") else f"/{api_path}"
        return self.http_request(method="GET", path=path, allow_redirects=False)