#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-92182 — pfSense CE XMLRPC auth bypass."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.protocols.http.pfsense_xmlrpc import Pfsense_xmlrpc


class Module(Scanner, Http_client, Pfsense_xmlrpc):
    __info__ = {
        "name": "pfSense CVE-2026-92182 detect",
        "description": "Tests admin-only XMLRPC reachability with low-priv credentials.",
        "author": ["LLCForge", "KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-92182"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-92182"],
        "tags": ["pfsense", "xmlrpc", "cve-2026-92182"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "exploits/linux/http/pfsense_cve_2026_92182_xmlrpc_rce",
                ],
            },
        },
    }

    username = OptString("", "pfSense username", required=True)
    password = OptString("", "pfSense password", required=True)

    def run(self):
        root = self.http_request("GET", "/", timeout=12)
        fp = bool(root and self.pfsense_fingerprint(root.text or ""))
        methods = self.pfsense_probe_methods()
        if not methods and not fp:
            return False
        self.set_info(
            severity="critical",
            cve="CVE-2026-92182",
            reason="pfSense XMLRPC",
            admin_methods=methods,
        )
        return bool(methods) or fp