#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Rucio REST API client mixin."""

from __future__ import annotations

import json
from typing import Any, Dict, Optional, Tuple

from core.framework.base_module import BaseModule


class Rucio(BaseModule):
    _rucio_account: str = ""
    _rucio_token: str = ""

    def rucio_headers(self) -> Dict[str, str]:
        hdr: Dict[str, str] = {"Content-Type": "application/json"}
        if self._rucio_account:
            hdr["X-Rucio-Account"] = self._rucio_account
        if self._rucio_token:
            hdr["X-Rucio-Auth-Token"] = self._rucio_token
        return hdr

    def rucio_api(self, method: str, suffix: str, *, json_body: Any = None) -> Tuple[int, str, Dict[str, str]]:
        path = suffix if suffix.startswith("/") else f"/{suffix}"
        kwargs: Dict[str, Any] = {
            "method": method,
            "path": path,
            "headers": self.rucio_headers(),
            "allow_redirects": False,
        }
        if json_body is not None:
            kwargs["data"] = json.dumps(json_body)
        resp = self.http_request(**kwargs)
        if not resp:
            return 0, "", {}
        headers = {k: v for k, v in (resp.headers or {}).items()}
        return int(resp.status_code or 0), (resp.text or ""), headers

    def rucio_ssh_challenge_token(self, account: str) -> Optional[str]:
        self._rucio_account = str(account)
        self._rucio_token = ""
        code, _, headers = self.rucio_api("GET", "/auth/ssh_challenge_token")
        if code >= 400:
            return None
        for key, val in headers.items():
            if key.lower() == "x-rucio-ssh-challenge-token":
                return str(val).strip()
        return None

    def rucio_whoami(self, token: str) -> Tuple[int, str]:
        self._rucio_token = str(token)
        return self.rucio_api("GET", "/accounts/whoami")[:2]