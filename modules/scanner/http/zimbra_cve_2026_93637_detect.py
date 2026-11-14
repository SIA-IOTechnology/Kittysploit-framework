#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-93637 — Zimbra GraphQL auth rate-limit bypass surface."""

import json

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Zimbra CVE-2026-93637 GraphQL detect",
        "description": (
            "Probes /service/extension/graphql and batched authenticate aliases "
            "for rate-limit bypass behavior (ZCS 10.1.0–10.1.21)."
        ),
        "author": ["KittySploit Team"],
        "severity": "low",
        "cve": ["CVE-2026-93637"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-93637",
        ],
        "tags": ["zimbra", "graphql", "bruteforce", "cve-2026-93637"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "auxiliary/admin/http/zimbra_cve_2026_93637_graphql_auth",
                ],
            },
        },
    }

    _GRAPHQL = "/service/extension/graphql"
    _PROBE_ACCOUNT = "graphql-probe@local"
    _ALIAS_COUNT = 14

    def _batched_mutation(self) -> str:
        parts = []
        for idx in range(self._ALIAS_COUNT):
            parts.append(
                f'a{idx}: authenticate(authInput: {{account: {{accountBy: name, key: "{self._PROBE_ACCOUNT}"}}, '
                f'password: "KsProbe{idx}!"}}) {{ authToken }}'
            )
        return "mutation { " + " ".join(parts) + " }"

    def run(self):
        ping = self.http_request(
            method="POST",
            path=self._GRAPHQL,
            headers={"Content-Type": "application/json"},
            data=json.dumps({"query": "query { __typename }"}),
        )
        if not ping or int(ping.status_code) not in (200, 400):
            return False

        batch = self.http_request(
            method="POST",
            path=self._GRAPHQL,
            headers={"Content-Type": "application/json"},
            data=json.dumps({"query": self._batched_mutation()}),
        )
        if not batch:
            return False
        if int(batch.status_code) == 503:
            return False
        if int(batch.status_code) != 200:
            self.set_info(
                severity="info",
                cve="CVE-2026-93637",
                reason="GraphQL present but batched authenticate probe inconclusive",
            )
            return True
        body = batch.text or ""
        errors = body.count("authentication failed") + body.count("AUTH_FAILED")
        if errors >= 3:
            self.set_info(
                severity="low",
                cve="CVE-2026-93637",
                reason="GraphQL batched authenticate accepts many failures without HTTP 503",
                batched_errors=errors,
            )
            return True
        self.set_info(severity="info", cve="CVE-2026-93637", reason="GraphQL extension reachable")
        return True