#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cozy-stack JSON API helpers."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from core.framework.base_module import BaseModule


class Cozy_stack(BaseModule):
    """Bearer-authenticated cozy-stack file API."""

    def _api_token(self) -> str:
        token = getattr(self, "api_token", "")
        if hasattr(token, "value"):
            return str(token.value or "").strip()
        return str(token or "").strip()

    def _cozy_headers(self) -> Dict[str, str]:
        token = self._api_token()
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/vnd.api+json",
        }

    @staticmethod
    def cozy_fingerprint(body: str) -> bool:
        blob = (body or "").lower()
        return "cozy" in blob or "mycozy" in blob

    def cozy_instance_ok(self) -> Tuple[bool, int]:
        resp = self.http_request(
            "GET",
            "/settings/instance",
            headers=self._cozy_headers(),
            timeout=15,
        )
        if not resp:
            return False, 0
        code = int(resp.status_code or 0)
        return code == 200, code

    def cozy_list_root_files(self) -> List[dict]:
        resp = self.http_request(
            "GET",
            "/files/io.cozy.files.root-dir",
            headers=self._cozy_headers(),
            timeout=20,
        )
        if not resp or int(resp.status_code or 0) != 200:
            return []
        try:
            payload = resp.json()
        except Exception:
            return []
        items = payload.get("included") or []
        return [x for x in items if isinstance(x, dict)]

    def cozy_move_file(self, file_id: str, target_dir_id: str) -> Tuple[int, str]:
        resp = self.http_request(
            "PATCH",
            f"/files/{file_id}",
            headers=self._cozy_headers(),
            json={
                "data": {
                    "type": "io.cozy.files",
                    "id": file_id,
                    "attributes": {"dir_id": target_dir_id},
                }
            },
            timeout=20,
        )
        if not resp:
            return 0, ""
        return int(resp.status_code or 0), (resp.text or "")[:400]