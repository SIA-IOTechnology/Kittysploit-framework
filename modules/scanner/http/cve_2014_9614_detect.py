#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Web Panel in Netsweeper before 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Netsweeper 4.0.5 - Default Weak Account Detection',
        'description': "The Web Panel in Netsweeper before 4.0.5 has a default password of 'branding' for the branding account, which makes it easier for remote attackers to obtain access via a request to webadmin/.",
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve2014', 'cve', 'netsweeper', 'default-login', 'packetstorm', 'xss', 'vuln'],
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
            'https://packetstormsecurity.com/files/download/133034/netsweeper-issues.tgz',
            'https://nvd.nist.gov/vuln/detail/CVE-2014-9614',
            'http://packetstormsecurity.com/files/133034/Netsweeper-Bypass-XSS-Redirection-SQL-Injection-Execution.html',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2014-9614',
    }

    def run(self):
        path = '/webadmin/auth/verification.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Origin': '{{BaseURL}}', 'Referer': '{{BaseURL}}/webadmin/start/'}, data='login=branding&password=branding&Submit=Login\n')
        if not r or r.status_code != 302:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('Location: ../common/', 'Location: ../start/', 'Set-Cookie: webadminU=',)
        if any(m in headers for m in header_any):
            self.set_info(severity='critical', reason='Netsweeper 4.0.5 - Default Weak Account detected', path=path)
            return True
        return False

