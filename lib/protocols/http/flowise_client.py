#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generic Flowise REST helpers."""

from __future__ import annotations

import json
import re
from typing import Any, Optional, Tuple

from core.framework.base_module import BaseModule
from lib.scanner.http.response_validation import parse_json_response


class Flowise(BaseModule):
    _VERSION_RE = re.compile(r"(\d+\.\d+\.\d+)", re.I)

    def _api(self, suffix: str) -> str:
        base = (getattr(self, "path", None) or "/").rstrip("/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base else suffix

    def flowise_version(self) -> str:
        r = self.http_request(method="GET", path=self._api("/api/v1/version"), allow_redirects=False)
        if not r:
            return ""
        body, _ = parse_json_response(r)
        if isinstance(body, dict):
            return str(body.get("version") or "")
        m = self._VERSION_RE.search(r.text or "")
        return m.group(1) if m else ""

    @staticmethod
    def flowise_version_tuple(version: str) -> tuple[int, int, int]:
        parts = [int(x) for x in re.findall(r"\d+", version or "")[:3]]
        while len(parts) < 3:
            parts.append(0)
        return parts[0], parts[1], parts[2]

    def flowise_register_login(self, email: str, password: str) -> bool:
        headers = {"x-request-from": "internal", "Content-Type": "application/json"}
        self.http_request(
            method="POST",
            path=self._api("/api/v1/account/register"),
            data=json.dumps({"user": {"name": "Kitty", "email": email, "credential": password}}),
            headers=headers,
            session=True,
        )
        login = self.http_request(
            method="POST",
            path=self._api("/api/v1/auth/login"),
            data=json.dumps({"email": email, "password": password}),
            headers=headers,
            session=True,
        )
        return bool(login and int(login.status_code) == 200)

    def flowise_public_chatflow_id(self) -> Optional[str]:
        for path in ("/api/v1/public-chatflows", "/api/v1/chatflows?type=CHATFLOW"):
            r = self.http_request(method="GET", path=self._api(path), allow_redirects=False)
            if not r or int(r.status_code) != 200:
                continue
            body, _ = parse_json_response(r)
            if isinstance(body, list) and body:
                first = body[0]
                if isinstance(first, dict):
                    return str(first.get("id") or first.get("chatflowid") or "")
            if isinstance(body, dict):
                items = body.get("data") or body.get("chatflows") or []
                if items and isinstance(items[0], dict):
                    return str(items[0].get("id") or "")
        return None

    def flowise_prediction(
        self,
        chatflow_id: str,
        question: str,
        *,
        uploads: Optional[list[dict[str, Any]]] = None,
        session: bool = False,
    ) -> Tuple[int, str]:
        payload: dict[str, Any] = {"question": question}
        if uploads:
            payload["uploads"] = uploads
        r = self.http_request(
            method="POST",
            path=self._api(f"/api/v1/prediction/{chatflow_id}"),
            data=json.dumps(payload),
            headers={"Content-Type": "application/json"},
            session=session,
            allow_redirects=False,
        )
        if not r:
            return 0, ""
        return int(r.status_code), r.text or ""