#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Detect exposed SharePoint WS-Federation trust endpoint used by CVE-2026-50522.

This module only fingerprints the attack surface (``/_trust/default.aspx`` +
SharePoint markers). It does **not** send BinaryFormatter / ysoserial gadgets.
"""

from __future__ import annotations

import uuid
from typing import List
from urllib.parse import urljoin

from kittysploit import *
from lib.protocols.http.http_client import Http_client

_TRUST_PATH = "/_trust/default.aspx"
_SP_HEADER_MARKERS = (
    "microsoftsharepointteamservices",
    "sprequestguid",
    "sprequestduration",
)


class Module(Scanner, Http_client):
    __info__ = {
        "name": "SharePoint CVE-2026-50522 Trust Endpoint Detection",
        "description": (
            "Detects an exposed on-prem SharePoint WS-Federation trust endpoint "
            "(/_trust/default.aspx) associated with CVE-2026-50522 (unauthenticated "
            "BinaryFormatter deserialization RCE). Surface detection only — no gadget "
            "payload is sent."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": "CVE-2026-50522",
        "references": [
            "https://github.com/4minx/CVE-2026-50522",
            "https://msrc.microsoft.com/",
            "https://www.sentinelone.com/vulnerability-database/cve-2026-50522/",
        ],
        "tags": [
            "web",
            "scanner",
            "sharepoint",
            "microsoft",
            "deserialization",
            "rce",
            "unauthenticated",
            "cve-2026-50522",
            "trust",
            "vuln",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "cost": 1.0,
            "noise": 0.35,
            "value": 1.4,
            "requires": {
                "min_endpoints": 0,
                "min_params": 0,
                "tech_hints_any": [],
                "tech_hints_all": [],
                "specializations_any": [],
                "risk_signals_any": [],
                "auth_session": False,
                "capabilities_any": [],
                "capabilities_all": [],
                "confidence_min": {},
                "confidence_min_any": {},
                "endpoint_pattern_any": [],
                "param_any": [],
                "api_surface_ready": False,
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "enterprise_panel", "from_detail": "sharepoint"},
                    {"capability": "rce_surface", "from_detail": "cve-2026-50522"},
                ],
                "consumes_capabilities": [],
                "option_bindings": {},
                "suggested_followups": [
                    "scanner/http/sharepoint_detect",
                    "scanner/http/sharepoint_toolshell_backdoor_detect",
                ],
            },
        },
    }

    require_sharepoint = OptBool(
        True,
        "Require SharePoint response headers/markers before reporting",
        required=False,
    )

    def _headers_blob(self, response) -> str:
        headers = getattr(response, "headers", None) or {}
        return "\n".join(f"{k}: {v}" for k, v in headers.items()).lower()

    def _looks_like_sharepoint(self, response) -> bool:
        if not response:
            return False
        blob = self._headers_blob(response)
        if any(m in blob for m in _SP_HEADER_MARKERS):
            return True
        body = (getattr(response, "text", None) or "")[:20000].lower()
        return any(
            m in body
            for m in (
                "sharepoint",
                "_layouts/15",
                "microsoftsharepointteamservices",
                "sp.js",
            )
        )

    def _analyze(self, response) -> List[str]:
        indicators: List[str] = []
        if not response:
            return indicators
        body = (getattr(response, "text", None) or "").lower()
        headers = getattr(response, "headers", None) or {}
        sc = str(headers.get("Set-Cookie") or headers.get("set-cookie") or "").lower()
        loc = str(headers.get("Location") or headers.get("location") or "")
        code = int(getattr(response, "status_code", 0) or 0)

        if code == 200:
            if any(x in body for x in ("sign in", "login", "msisauthenticated", "signout.aspx")):
                indicators.append("LOGIN_PAGE")
            if any(x in body for x in ("securitytoken", "requestsecuritytoken", "wsignin")):
                indicators.append("TOKEN_HANDLER")
            if "amsi" in body and ("blocked" in body or "detected" in body):
                indicators.append("AMSI_BLOCKED")
            if any(x in sc for x in ("msisauth", "fedauth", ".aspxauth")):
                indicators.append("AUTH_COOKIE")
            if self._looks_like_sharepoint(response):
                indicators.append("SHAREPOINT")
        elif code in (301, 302, 303, 307, 308):
            low_loc = loc.lower()
            if any(x in low_loc for x in ("_trust", "login", "signin", "authenticate")):
                indicators.append("REDIRECT_AUTH")
            indicators.append(f"HTTP_{code}")
        elif code in (400, 401, 403, 405, 500, 503):
            indicators.append(f"HTTP_{code}")
            if self._looks_like_sharepoint(response):
                indicators.append("SHAREPOINT")
        return indicators

    def _benign_wresult(self) -> str:
        """Minimal WS-Fed token without serialized gadget cookie."""
        guid = uuid.uuid4().hex
        token = (
            '<sc:SecurityContextToken xmlns:sc="http://schemas.xmlsoap.org/ws/2005/02/sc">'
            f"<sc:Identifier>urn:unique-id:securitycontext:{guid}</sc:Identifier>"
            "</sc:SecurityContextToken>"
        )
        return (
            '<t:RequestSecurityTokenResponse xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust">'
            f"<t:RequestedSecurityToken>{token}</t:RequestedSecurityToken>"
            "</t:RequestSecurityTokenResponse>"
        )

    def _base_url(self) -> str:
        scheme = "https" if bool(getattr(self, "ssl", True)) else "http"
        port = int(getattr(self, "port", 443) or 443)
        host = str(getattr(self, "target", "") or "")
        return f"{scheme}://{host}:{port}"

    def run(self):
        root = self.http_request(method="GET", path="/", allow_redirects=True)
        sp_seen = self._looks_like_sharepoint(root)
        if not sp_seen:
            for path in ("/_api/web", "/_layouts/15/start.aspx"):
                r = self.http_request(method="GET", path=path, allow_redirects=False)
                if self._looks_like_sharepoint(r):
                    sp_seen = True
                    break

        if self.require_sharepoint and not sp_seen:
            return False

        trust_get = self.http_request(
            method="GET",
            path=_TRUST_PATH,
            allow_redirects=False,
        )
        get_indicators = self._analyze(trust_get)
        get_code = int(getattr(trust_get, "status_code", 0) or 0) if trust_get else 0

        wctx = urljoin(self._base_url().rstrip("/") + "/", "")
        trust_post = self.http_request(
            method="POST",
            path=_TRUST_PATH,
            data={
                "wa": "wsignin1.0",
                "wctx": wctx,
                "wresult": self._benign_wresult(),
            },
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
            },
            allow_redirects=False,
        )
        post_indicators = self._analyze(trust_post)
        post_code = int(getattr(trust_post, "status_code", 0) or 0) if trust_post else 0

        exposed = False
        for code, indicators in ((get_code, get_indicators), (post_code, post_indicators)):
            if code and code not in (404, 0):
                exposed = True
                break
            if indicators:
                exposed = True
                break

        if not exposed:
            return False

        host = str(getattr(self, "target", "") or "").lower()
        if host.endswith(".sharepoint.com"):
            return False

        merged = sorted(set(get_indicators + post_indicators + (["SHAREPOINT"] if sp_seen else [])))
        reason = (
            f"Exposed SharePoint trust endpoint {_TRUST_PATH} "
            f"(GET={get_code}, POST={post_code}; indicators={','.join(merged) or 'NONE'}). "
            "CVE-2026-50522 attack surface — gadget-based confirmation not performed by this scanner."
        )
        self.set_info(
            severity="high",
            cve="CVE-2026-50522",
            service="sharepoint",
            endpoint=_TRUST_PATH,
            path=_TRUST_PATH,
            indicators=",".join(merged),
            http_get=get_code,
            http_post=post_code,
            reason=reason,
        )
        return True
