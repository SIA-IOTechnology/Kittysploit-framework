#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""atomic-server HTTP API helpers."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from core.framework.base_module import BaseModule


class Atomic_server(BaseModule):
    """Fingerprint and /download endpoint for atomic-server deployments."""

    @staticmethod
    def parse_version(text: str) -> str:
        match = re.search(
            r"atomic[_\-\s]*server[/\s:v]*([\d]+\.[\d]+(?:\.[\d]+)?)",
            text or "",
            re.I,
        )
        if match:
            return match.group(1)
        match = re.search(r'"version"\s*:\s*"([\d.]+)"', text or "")
        return match.group(1) if match else ""

    @classmethod
    def version_tuple(cls, version: str) -> Tuple[int, ...]:
        parts: List[int] = []
        for token in str(version or "").split("."):
            digits = "".join(ch for ch in token if ch.isdigit())
            if digits:
                parts.append(int(digits))
        while len(parts) < 3:
            parts.append(0)
        return tuple(parts[:4])

    @classmethod
    def version_less_than(cls, left: str, right: str) -> bool:
        a = cls.version_tuple(left)
        b = cls.version_tuple(right)
        for i in range(max(len(a), len(b))):
            av = a[i] if i < len(a) else 0
            bv = b[i] if i < len(b) else 0
            if av < bv:
                return True
            if av > bv:
                return False
        return False

    def as_fingerprint(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "reachable": False,
            "is_atomic": False,
            "version": "",
        }
        resp = self.http_request(method="GET", path="/")
        if not resp or int(resp.status_code or 0) >= 500:
            return result
        result["reachable"] = True
        headers = {k.lower(): v for k, v in (resp.headers or {}).items()}
        banner = " ".join(
            headers.get(k, "") for k in ("server", "x-powered-by") if headers.get(k)
        )
        body = (resp.text or "")[:2000]
        haystack = f"{banner} {body}".lower()
        if "atomic" in haystack:
            result["is_atomic"] = True
            ver = self.parse_version(body) or self.parse_version(banner)
            if ver:
                result["version"] = ver
        ver_resp = self.http_request(method="GET", path="/version")
        if ver_resp and int(ver_resp.status_code or 0) == 200:
            try:
                vdata = ver_resp.json()
                result["version"] = str(
                    vdata.get("version") or vdata.get("server_version") or result["version"]
                )
            except Exception:
                pass
        return result

    def as_download(
        self,
        internal_id: str,
        *,
        allow_redirects: bool = True,
    ) -> Optional[Any]:
        return self.http_request(
            method="GET",
            path="/download",
            params={"internalId": internal_id},
            allow_redirects=allow_redirects,
        )

    def as_setup_invite(self) -> Optional[str]:
        resp = self.http_request(
            method="GET",
            path="/setup",
            headers={"Accept": "application/json"},
        )
        if not resp or int(resp.status_code or 0) != 200:
            return None
        ctype = str((resp.headers or {}).get("Content-Type", "")).lower()
        if "json" in ctype:
            try:
                data = resp.json()
                invite = data.get("invite") or data.get("invite_url") or data.get("url")
                if invite:
                    return str(invite)
            except Exception:
                pass
        text = resp.text or ""
        match = re.search(r'(https?://[^\s"\'<]+/invite/[A-Za-z0-9_=-]+)', text)
        if match:
            return match.group(1)
        match = re.search(r'["\']invite["\']\s*:\s*["\']([^"\']+)["\']', text)
        if match:
            invite = match.group(1)
            if invite.startswith("http"):
                return invite
            return invite if invite.startswith("/invite") else f"/invite/{invite.lstrip('/')}"
        return None

    def as_bookmark_fetch(self, target_url: str) -> Tuple[int, str]:
        resp = self.http_request(
            method="GET",
            path="/bookmark",
            params={"url": target_url},
        )
        if not resp:
            return 0, ""
        return int(resp.status_code or 0), (resp.text or "")