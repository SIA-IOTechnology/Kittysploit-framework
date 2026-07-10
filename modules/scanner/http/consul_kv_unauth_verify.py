#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Verify unauthenticated Consul KV writes (reversible probe)."""

import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Consul KV Unauthenticated Write Verification",
        "description": "Tests reversible Consul /v1/kv PUT/DELETE when write_probe is enabled.",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "tags": ["consul", "hashicorp", "scanner", "unauth", "verify", "misconfig"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "chain": {"produces_capabilities": ["unauth_write", "misconfig_surface"]},
        },
    }

    write_probe = OptBool(False, "Perform reversible KV PUT/DELETE test (requires approval)", required=False)

    def run(self):
        r = self.http_request(method="GET", path="/v1/agent/self", allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        if not self.write_probe:
            self.set_info(
                severity="high",
                reason="Consul agent API readable; enable write_probe to confirm KV writes",
                confidence="medium",
            )
            return True

        key = f"kittysploit-probe-{secrets.token_hex(4)}"
        value = secrets.token_hex(6)
        put = self.http_request(
            method="PUT",
            path=f"/v1/kv/{key}",
            data=value,
            allow_redirects=False,
        )
        if not put or put.status_code != 200 or (put.text or "").strip() != "true":
            return False
        delete = self.http_request(method="DELETE", path=f"/v1/kv/{key}", allow_redirects=False)
        self.set_info(
            severity="critical",
            reason="Consul accepted unauthenticated KV write",
            key=key,
            confidence="high",
            cleaned=bool(delete and delete.status_code == 200),
        )
        return True
