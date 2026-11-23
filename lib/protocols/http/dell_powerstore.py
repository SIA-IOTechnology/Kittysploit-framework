#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Dell PowerStore REST API helpers (unauthenticated fingerprint + session auth)."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

from core.framework.base_module import BaseModule


class Dell_powerstore(BaseModule):
    """PowerStore /api/rest client mixin for scanner and exploit modules."""

    _dell_emc_token: str = ""

    @staticmethod
    def ps_parse_version_parts(version: str) -> List[int]:
        parts: List[int] = []
        for token in str(version or "").replace("-", ".").split("."):
            digits = "".join(ch for ch in token if ch.isdigit())
            if digits:
                parts.append(int(digits))
        while len(parts) < 4:
            parts.append(0)
        return parts[:6]

    @classmethod
    def ps_version_less_than(cls, left: str, right: str) -> bool:
        a = cls.ps_parse_version_parts(left)
        b = cls.ps_parse_version_parts(right)
        for index in range(max(len(a), len(b))):
            av = a[index] if index < len(a) else 0
            bv = b[index] if index < len(b) else 0
            if av < bv:
                return True
            if av > bv:
                return False
        return False

    def ps_api_path(self, suffix: str) -> str:
        base = str(getattr(self, "path", None) or "").strip().rstrip("/")
        suffix = suffix if suffix.startswith("/") else f"/{suffix}"
        return f"{base}{suffix}" if base else suffix

    def _ps_headers(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        headers = {"Content-Type": "application/json", "Connection": "close"}
        if self._dell_emc_token:
            headers["DELL-EMC-TOKEN"] = self._dell_emc_token
        if extra:
            headers.update(extra)
        return headers

    @staticmethod
    def ps_json_body(resp: Any) -> Any:
        if not resp:
            return None
        text = (getattr(resp, "text", None) or "").strip()
        if not text:
            return None
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None

    @staticmethod
    def ps_entries(data: Any) -> List[dict]:
        if not isinstance(data, dict):
            return []
        raw = data.get("entries")
        if isinstance(raw, list):
            return [e for e in raw if isinstance(e, dict)]
        return [data]

    @staticmethod
    def ps_entry_content(entry: dict) -> dict:
        content = entry.get("content")
        return content if isinstance(content, dict) else entry

    def ps_rest(
        self,
        method: str,
        api_suffix: str,
        json_body: Optional[dict] = None,
        *,
        timeout: Optional[int] = None,
    ) -> Tuple[int, Any, Any]:
        kwargs: Dict[str, Any] = {
            "method": method,
            "path": self.ps_api_path(api_suffix),
            "headers": self._ps_headers(),
        }
        if json_body is not None:
            kwargs["data"] = json.dumps(json_body)
        if timeout is not None:
            kwargs["timeout"] = timeout
        resp = self.http_request(**kwargs)
        if not resp:
            return 0, None, None
        code = int(resp.status_code or 0)
        return code, self.ps_json_body(resp), resp

    def ps_login(self, username: str, password: str) -> bool:
        code, body, resp = self.ps_rest(
            "POST",
            "/api/rest/login_sessions",
            {"username": username, "password": password, "is_async": False},
        )
        if code not in (200, 201) or not resp:
            return False
        token = resp.headers.get("DELL-EMC-TOKEN") or resp.headers.get("EMC_CSRF_TOKEN")
        if not token:
            return False
        self._dell_emc_token = str(token)
        return True

    def ps_application_instance(self) -> Tuple[int, Optional[dict]]:
        code, data, _ = self.ps_rest("GET", "/api/rest/application_instance")
        if code != 200 or not isinstance(data, dict):
            return code, None
        for entry in self.ps_entries(data):
            content = self.ps_entry_content(entry)
            vendor = str(content.get("manufacturer", "")).lower()
            model = str(content.get("model_name", "")).lower()
            if "dell" in vendor or "powerstore" in model:
                version = (
                    content.get("revision_level")
                    or content.get("software_version")
                    or ""
                )
                return code, {
                    "is_powerstore": True,
                    "version": str(version or "unknown"),
                    "manufacturer": content.get("manufacturer", ""),
                    "model_name": content.get("model_name", ""),
                }
        return code, {"is_powerstore": False, "version": ""}

    def ps_sdnas_nodes(self) -> Tuple[int, List[str]]:
        code, data, _ = self.ps_rest("GET", "/api/rest/sdnas_node")
        if code != 200:
            return code, []
        ids: List[str] = []
        for entry in self.ps_entries(data):
            content = self.ps_entry_content(entry)
            node_id = content.get("id") or entry.get("id")
            if node_id:
                ids.append(str(node_id))
        return code, ids

    def ps_sdnas_diagnose_network(self, node_id: str, nslookup_host: str) -> Tuple[int, str]:
        path = f"/api/rest/sdnas_node/{node_id}/action/diagnose_network"
        code, data, _ = self.ps_rest(
            "POST",
            path,
            {"nslookup_host": nslookup_host},
        )
        if code not in (200, 201) or not isinstance(data, dict):
            return code, ""
        output = data.get("output")
        if output is None and isinstance(data.get("content"), dict):
            output = data["content"].get("output")
        if output is None:
            output = json.dumps(data, indent=2)
        return code, str(output or "")