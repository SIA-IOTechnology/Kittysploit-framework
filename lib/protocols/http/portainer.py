#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Portainer HTTP API helpers."""

from __future__ import annotations

import json
from typing import Any, Optional

from core.framework.base_module import BaseModule

DOCKER_ENDPOINT_TYPES = (1, 2, 4)


class Portainer(BaseModule):
    """Authenticated Portainer API client."""

    _jwt: str = ""

    def _pt_join(self, suffix: str) -> str:
        base = (getattr(self, "path", None) or "/").rstrip("/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base else suffix

    def pt_request(
        self,
        method: str,
        api_path: str,
        *,
        json_body: Optional[dict] = None,
        params: Optional[dict] = None,
        timeout: int = 30,
    ) -> tuple[int, Any]:
        headers = {"Connection": "close"}
        if self._jwt:
            headers["Authorization"] = f"Bearer {self._jwt}"
        data = json.dumps(json_body) if json_body is not None else None
        if json_body is not None:
            headers["Content-Type"] = "application/json"
        resp = self.http_request(
            method=method,
            path=self._pt_join(api_path),
            headers=headers,
            data=data,
            params=params,
            timeout=timeout,
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

    def pt_login(self, username: str, password: str) -> bool:
        code, body = self.pt_request(
            "POST",
            "/api/auth",
            json_body={"Username": username, "Password": password},
        )
        if code != 200 or not isinstance(body, dict):
            return False
        token = body.get("jwt")
        if not token:
            return False
        self._jwt = str(token)
        return True

    def pt_version(self) -> str:
        for sub in ("/api/system/status", "/api/status"):
            code, body = self.pt_request("GET", sub)
            if code == 200 and isinstance(body, dict):
                return str(body.get("Version") or "")
        return ""

    def pt_pick_docker_endpoint(self) -> Optional[int]:
        code, body = self.pt_request("GET", "/api/endpoints")
        if code != 200 or not isinstance(body, list):
            return None
        for row in body:
            if isinstance(row, dict) and int(row.get("Type") or 0) in DOCKER_ENDPOINT_TYPES:
                return int(row["Id"])
        return None

    def pt_image_present(self, endpoint_id: int, image: str) -> bool:
        code, body = self.pt_request(
            "GET",
            f"/api/endpoints/{endpoint_id}/docker/images/json",
        )
        if code != 200 or not isinstance(body, list):
            return False
        for img in body:
            tags = img.get("RepoTags") if isinstance(img, dict) else None
            if isinstance(tags, list) and image in tags:
                return True
        return False

    def pt_pull_image(self, endpoint_id: int, image: str) -> bool:
        code, _ = self.pt_request(
            "POST",
            f"/api/endpoints/{endpoint_id}/docker/images/create",
            params={"fromImage": image},
            timeout=300,
        )
        return code == 200

    def pt_create_container(self, endpoint_id: int, image: str, host_cmd: str) -> Optional[str]:
        payload = {
            "Image": image,
            "Entrypoint": [],
            "Cmd": ["/bin/sh", "-c", host_cmd],
            "HostConfig": {
                "Binds": ["/:/host"],
                "Privileged": True,
                "PidMode": "host",
            },
        }
        code, body = self.pt_request(
            "POST",
            f"/api/endpoints/{endpoint_id}/docker/containers/create",
            json_body=payload,
        )
        if code not in (200, 201) or not isinstance(body, dict):
            return None
        cid = body.get("Id")
        return str(cid) if cid else None

    def pt_start_container(self, endpoint_id: int, container_id: str) -> bool:
        code, _ = self.pt_request(
            "POST",
            f"/api/endpoints/{endpoint_id}/docker/containers/{container_id}/start",
        )
        return code in (204, 304)

    def pt_remove_container(self, endpoint_id: int, container_id: str) -> bool:
        self.pt_request(
            "POST",
            f"/api/endpoints/{endpoint_id}/docker/containers/{container_id}/stop",
            timeout=15,
        )
        code, _ = self.pt_request(
            "DELETE",
            f"/api/endpoints/{endpoint_id}/docker/containers/{container_id}",
            params={"force": "1"},
            timeout=15,
        )
        return code in (200, 204)