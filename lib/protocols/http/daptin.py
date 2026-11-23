#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Daptin REST API helpers."""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from core.framework.base_module import BaseModule


class Daptin(BaseModule):
    def daptin_fingerprint(self) -> bool:
        for path in ("/", "/api", "/apispec.raw"):
            resp = self.http_request(method="GET", path=path)
            if not resp:
                continue
            text = (resp.text or "").lower()
            if "daptin" in text or (path == "/api" and int(resp.status_code or 0) in (200, 401)):
                return True
        return False

    def daptin_entity_list(self, entity: str, sort: str) -> Tuple[int, str]:
        path = f"/api/{entity}"
        resp = self.http_request(method="GET", path=path, params={"sort": sort})
        if not resp:
            return 0, ""
        return int(resp.status_code or 0), (resp.text or "")