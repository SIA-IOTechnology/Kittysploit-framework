#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Token tampering probe (missing integrity check)."""

from __future__ import annotations

import base64
from typing import List, Optional, Tuple

from core.framework.base_module import BaseModule


class Token_integrity(BaseModule):
    """Bit-flip cookie/token acceptance probe."""

    @staticmethod
    def decode_token(token: str) -> Tuple[bytearray, str]:
        try:
            raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
            return bytearray(raw), "b64"
        except Exception:
            return bytearray(str(token or "").encode()), "raw"

    @staticmethod
    def encode_token(data: bytearray, kind: str) -> str:
        if kind == "b64":
            return base64.urlsafe_b64encode(bytes(data)).decode().rstrip("=")
        return data.decode(errors="ignore")

    def send_token_cookie(self, token: str, cookie_name: str, path: str = "/"):
        return self.http_request(
            "GET",
            path,
            cookies={cookie_name: token},
            allow_redirects=False,
            timeout=15,
        )

    def token_flip_probe(
        self,
        token: str,
        cookie_name: str,
        flip_index: Optional[int] = None,
        scan_all: bool = False,
    ) -> List[dict]:
        data, kind = self.decode_token(token)
        base = self.send_token_cookie(token, cookie_name)
        base_code = int(base.status_code or 0) if base else 0
        base_len = len(base.content or b"") if base else 0
        indices = range(len(data)) if scan_all else [int(flip_index or 0)]
        accepted: List[dict] = []
        for idx in indices:
            if idx is None or idx >= len(data):
                continue
            mutated = bytearray(data)
            mutated[idx] ^= 0x01
            flipped = self.encode_token(mutated, kind)
            resp = self.send_token_cookie(flipped, cookie_name)
            if not resp:
                continue
            code = int(resp.status_code or 0)
            if code in (401, 403) or code >= 500:
                continue
            length = len(resp.content or b"")
            if code != base_code or length != base_len:
                accepted.append({"index": idx, "status_code": code, "length": length})
        return accepted