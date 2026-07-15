#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Entra ID OAuth helpers (mixin)."""

from __future__ import annotations

import base64
import json
from typing import Any, Dict, Optional, Tuple

import requests

try:
    import msal
except ImportError:
    msal = None


class EntraTokenMixin:
    """Mixin for modules that mint or validate Entra ID client_credentials tokens."""

    @staticmethod
    def entra_decode_jwt_claims(token: str) -> Dict[str, Any]:
        parts = (token or "").split(".")
        if len(parts) < 2:
            return {}
        payload = parts[1]
        payload += "=" * (-len(payload) % 4)
        try:
            raw = base64.urlsafe_b64decode(payload)
            data = json.loads(raw.decode("utf-8", errors="replace"))
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    @staticmethod
    def entra_build_api_default_scope(victim_api: str) -> str:
        api = str(victim_api or "").strip()
        if not api:
            raise ValueError("victim_api is required when scope is not set")
        if not api.startswith("api://") and not api.startswith("https://"):
            api = f"api://{api}"
        return f"{api}/.default"

    @staticmethod
    def entra_is_aad_line_issuer(issuer: str) -> bool:
        iss = str(issuer or "").strip().lower()
        if not iss:
            return False
        if "b2clogin.com" in iss:
            return False
        return (
            "login.microsoftonline.com" in iss
            or "sts.windows.net" in iss
            or "windows.net" in iss
        )

    def entra_http_session(self) -> Optional[requests.Session]:
        session = getattr(self, "session", None)
        return session if isinstance(session, requests.Session) else None

    def entra_resolve_scope(self, *, scope: str = "", victim_api: str = "") -> str:
        custom = str(scope or "").strip()
        if custom:
            return custom
        victim = str(victim_api or "").strip()
        if not victim:
            raise ValueError("Set scope or victim_api to build the client_credentials scope")
        return self.entra_build_api_default_scope(victim)

    def entra_mint_token_raw(
        self,
        *,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        scope: str,
        timeout: int = 15,
    ) -> Tuple[Optional[str], Dict[str, Any]]:
        url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
        data = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": scope,
        }
        http = self.entra_http_session() or requests
        try:
            resp = http.post(url, data=data, timeout=timeout)
            body = resp.json() if resp.content else {}
        except Exception as exc:
            return None, {"error": "request_failed", "error_description": str(exc)}
        if not isinstance(body, dict):
            return None, {"error": "invalid_response", "error_description": str(body)[:300]}
        token = body.get("access_token")
        if not token:
            return None, body
        return str(token), body

    def entra_mint_token_msal(
        self,
        *,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        scope: str,
    ) -> Tuple[Optional[str], Dict[str, Any]]:
        if msal is None:
            return None, {
                "error": "msal_missing",
                "error_description": "Install msal or use raw HTTP token acquisition",
            }
        authority = f"https://login.microsoftonline.com/{tenant_id}"
        app = msal.ConfidentialClientApplication(
            client_id,
            authority=authority,
            client_credential=client_secret,
        )
        result = app.acquire_token_for_client(scopes=[scope])
        if not isinstance(result, dict):
            return None, {"error": "invalid_msal_response"}
        token = result.get("access_token")
        if not token:
            return None, result
        return str(token), result

    def entra_mint_client_credentials_token(
        self,
        *,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        scope: str,
        use_msal: bool = False,
        timeout: int = 15,
    ) -> Tuple[Optional[str], Dict[str, Any]]:
        if use_msal:
            return self.entra_mint_token_msal(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret,
                scope=scope,
            )
        return self.entra_mint_token_raw(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
            scope=scope,
            timeout=timeout,
        )

    def entra_acquire_aad_line_token(
        self,
        *,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        scope: str,
        use_msal: bool = False,
        timeout: int = 15,
    ) -> Tuple[Optional[str], Dict[str, Any], Dict[str, Any]]:
        """Mint a token; return (token, claims, error_meta)."""
        token, meta = self.entra_mint_client_credentials_token(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
            scope=scope,
            use_msal=use_msal,
            timeout=timeout,
        )
        if not token:
            return None, {}, meta

        claims = self.entra_decode_jwt_claims(token)
        iss = str(claims.get("iss", ""))
        if not self.entra_is_aad_line_issuer(iss):
            return None, claims, {
                "error": "invalid_issuer",
                "error_description": f"Token issuer is not AAD-line: {iss or '?'}",
            }
        return token, claims, {}
