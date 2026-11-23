#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PHP session.upload_progress precondition helpers."""

from __future__ import annotations

from typing import Dict

from core.framework.base_module import BaseModule


class Php_session_upload(BaseModule):
    """Heuristics for serialize-handler mismatch targets."""

    def php_session_preconditions(self, path: str = "/") -> Dict[str, object]:
        result: Dict[str, object] = {
            "reachable": False,
            "upload_progress_enabled": None,
            "handler_mismatch_likely": None,
            "phpinfo_found": False,
        }
        resp = self.http_request("GET", path, timeout=15)
        if not resp:
            return result
        result["reachable"] = int(resp.status_code or 0) < 500
        text = resp.text or ""
        if "session.upload_progress.enabled" in text:
            result["phpinfo_found"] = True
            idx = text.find("session.upload_progress.enabled")
            snippet = text[idx : idx + 120]
            result["upload_progress_enabled"] = "1" in snippet
        for header, value in (resp.headers or {}).items():
            if header.lower() == "set-cookie" and "phpsessid" in str(value).lower():
                result["handler_mismatch_likely"] = True
                break
        return result