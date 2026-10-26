#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apache Struts2 CVE-2024-53677 file upload action fingerprint."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Apache Struts2 CVE-2024-53677 Upload Detect",
        "description": "Probes common Struts file-upload .action endpoints for CVE-2024-53677 chain.",
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2024-53677"],
        "tags": ["web", "scanner", "struts2", "upload", "cve-2024-53677"],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-53677"],
        "agent": {
            "risk": "active",
            "effects": ["network_probe"],
            "expected_requests": 4,
            "reversible": True,
            "approval_required": False,
            "produces": ["tech_hints", "endpoints"],
            "chain": {
                "suggested_followups": ["exploits/multi/http/struts2_cve_2024_53677_rce"],
            },
        },
    }

    upload_paths = OptString(
        "/upload.action,/fileupload.action,/image/upload.action",
        "Comma-separated upload action paths",
        required=False,
    )

    def run(self):
        hits = []
        for raw in str(self.upload_paths or "").split(","):
            path = raw.strip()
            if not path:
                continue
            if not path.startswith("/"):
                path = "/" + path
            r = self.http_request("GET", path, allow_redirects=False)
            if not r:
                continue
            code = int(r.status_code or 0)
            body = (r.text or "").lower()
            if code < 500 and ("struts" in body or "upload" in body or code in (200, 302, 405)):
                hits.append(path)
        if not hits:
            return False
        self.set_info(
            severity="critical",
            cve="CVE-2024-53677",
            reason=f"Struts upload actions reachable: {', '.join(hits[:5])}",
            paths=hits,
            confidence="medium",
        )
        return True
