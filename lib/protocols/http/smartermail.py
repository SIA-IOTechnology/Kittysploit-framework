#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SmarterMail REST API helpers."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Optional, Tuple

from core.framework.base_module import BaseModule


class Smartermail(BaseModule):
    _sm_token: str = ""

    def sm_fingerprint(self) -> Tuple[int, str]:
        resp = self.http_request(method="GET", path="/interface/root")
        if not resp:
            return 0, ""
        build = ""
        text = resp.text or ""
        if "SmarterMail" in text:
            match = re.search(r"Build (\d+)", text)
            if match:
                build = match.group(1)
        return int(resp.status_code or 0), build

    def sm_login(self, username: str, password: str) -> Optional[str]:
        payloads = (
            {"username": username, "password": password},
            {"emailAddress": username, "password": password},
            {"user": username, "pass": password},
        )
        for body in payloads:
            resp = self.http_request(
                method="POST",
                path="/api/v1/auth/authenticate-user",
                data=json.dumps(body),
                headers={"Content-Type": "application/json"},
            )
            if not resp or int(resp.status_code or 0) != 200:
                continue
            try:
                data = resp.json()
            except Exception:
                continue
            token = data.get("accessToken") or data.get("token")
            if not token and isinstance(data.get("data"), dict):
                token = data["data"].get("accessToken")
            if token:
                self._sm_token = str(token)
                return self._sm_token
        return None

    def sm_auth_headers(self) -> Dict[str, str]:
        hdr = {"Content-Type": "application/json"}
        if self._sm_token:
            hdr["Authorization"] = f"Bearer {self._sm_token}"
        return hdr

    def sm_filestorage_upload_json(self, remote_name: str, content: str) -> Tuple[int, str]:
        resp = self.http_request(
            method="POST",
            path="/api/v1/filestorage/upload",
            headers=self.sm_auth_headers(),
            data=json.dumps({"fileName": remote_name, "content": content}),
        )
        if not resp:
            return 0, ""
        return int(resp.status_code or 0), (resp.text or "")[:500]