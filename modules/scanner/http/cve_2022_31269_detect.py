#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Linear eMerge E3-Series devices are susceptible to information disclosure."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Linear eMerge E3-Series - Information Disclosure Detection',
        'description': 'Linear eMerge E3-Series devices are susceptible to information disclosure. Admin credentials are stored in clear text at the endpoint /test.txt in situations where the default admin credentials have been changed. An attacker can obtain admin credentials, access the admin dashboard, control building access and cameras, and access employee information.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'emerge', 'exposure', 'packetstorm', 'nortekcontrol', 'vuln'],
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
            'https://packetstormsecurity.com/files/167990/Nortek-Linear-eMerge-E3-Series-Credential-Disclosure.html',
            'https://www.nortekcontrol.com/access-control/',
            'https://eg.linkedin.com/in/omar-1-hashem',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-31269',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2022-31269',
    }

    def run(self):
        r = self.http_request(method="GET", path='/test.txt', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('ID=', 'Password=',)
        header_any = ('text/plain',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="Linear eMerge E3-Series - Information Disclosure detected",
                path='/test.txt',
            )
            return True
        return False

