#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generic HTTP helpers for OpenBullet2 API (empty X-Api-Key auth bypass on默认 installs)."""

from __future__ import annotations

import json
from typing import Any, Optional

from core.framework.base_module import BaseModule


class Openbullet2(BaseModule):
    """OpenBullet2 REST client helpers."""

    _API_HEADERS = {"X-Api-Key": "", "Content-Type": "application/json"}

    def _ob_join(self, suffix: str) -> str:
        base = (getattr(self, "path", None) or "/").rstrip("/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base else suffix

    def ob_api(
        self,
        method: str,
        api_path: str,
        *,
        json_body: Optional[dict] = None,
        params: Optional[dict] = None,
    ) -> tuple[int, Any]:
        resp = self.http_request(
            method=method,
            path=self._ob_join(api_path),
            headers=dict(self._API_HEADERS),
            data=json.dumps(json_body) if json_body is not None else None,
            params=params,
            allow_redirects=False,
        )
        if not resp:
            return 0, None
        code = int(resp.status_code or 0)
        text = resp.text or ""
        try:
            body = json.loads(text) if text.strip().startswith(("{", "[")) else text
        except json.JSONDecodeError:
            body = text
        return code, body

    def ob_version(self) -> Optional[str]:
        code, body = self.ob_api("GET", "/api/v1/info/update")
        if code != 200 or not isinstance(body, dict):
            return None
        ver = body.get("currentVersion")
        return str(ver) if ver else None

    def ob_server_os(self) -> str:
        code, body = self.ob_api("GET", "/api/v1/info/server")
        if code == 200 and isinstance(body, dict):
            return str(body.get("operatingSystem") or "")
        return ""

    def ob_create_config(self) -> Optional[str]:
        code, body = self.ob_api("POST", "/api/v1/config")
        if code == 200 and isinstance(body, dict) and body.get("id"):
            return str(body["id"])
        return None

    def ob_delete_config(self, config_id: str) -> bool:
        code, _ = self.ob_api("DELETE", "/api/v1/config", params={"id": config_id})
        return code == 200

    def ob_put_config_script(self, config_id: str, startup_csharp: str) -> bool:
        code, _ = self.ob_api(
            "PUT",
            "/api/v1/config",
            json_body={
                "id": config_id,
                "metadata": {},
                "settings": {},
                "startupLoliCodeScript": startup_csharp,
            },
        )
        return code == 200

    def ob_create_multirun_job(self, config_id: str, *, proxy_path: str = "") -> Optional[str]:
        payload: dict[str, Any] = {
            "startCondition": {"_polyTypeName": "relativeTimeStartCondition"},
            "configId": config_id,
            "proxyMode": "on" if proxy_path else "off",
            "dataPool": {
                "_polyTypeName": "rangeDataPool",
                "wordlistType": "Default",
                "start": 1,
                "amount": 1,
                "step": 1,
            },
        }
        if proxy_path:
            payload["proxySources"] = [
                {
                    "_polyTypeName": "fileProxySource",
                    "fileName": proxy_path,
                    "defaultType": "http",
                }
            ]
        code, body = self.ob_api("POST", "/api/v1/job/multi-run", json_body=payload)
        if code == 200 and isinstance(body, dict) and body.get("id"):
            return str(body["id"])
        return None

    def ob_job_start(self, job_id: str) -> bool:
        code, _ = self.ob_api(
            "POST",
            "/api/v1/job/start",
            json_body={"jobId": job_id, "wait": False},
        )
        return code == 200

    def ob_job_abort(self, job_id: str) -> bool:
        code, _ = self.ob_api(
            "POST",
            "/api/v1/job/abort",
            json_body={"jobId": job_id, "wait": False},
        )
        return code == 200

    def ob_job_delete(self, job_id: str) -> bool:
        code, _ = self.ob_api("DELETE", "/api/v1/job", params={"id": job_id})
        return code == 200