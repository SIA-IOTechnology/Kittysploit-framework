#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PrismaWEB is susceptible to credential disclosure."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'PrismaWEB - Credentials Disclosure Detection',
        'description': 'PrismaWEB is susceptible to credential disclosure. The vulnerability exists due to the disclosure of hard-coded credentials allowing an attacker to effectively bypass authentication of PrismaWEB with administrator privileges. The credentials can be disclosed by simply navigating to the login_par.js JavaScript page that holds the username and password for the management interface that are being used via the Login() function in /scripts/functions_cookie.js script.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'prismaweb', 'exposure', 'edb', 'prismaindustriale', 'vuln'],
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
            'https://www.zeroscience.mk/en/vulnerabilities/ZSL-2018-5453.php',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-9161',
            'https://www.exploit-db.com/exploits/44276/',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2018-9161',
    }

    def run(self):
        r = self.http_request(method="GET", path='/user/scripts/login_par.js', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('txtChkUser', 'txtChkPassword',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='critical',
                reason="PrismaWEB - Credentials Disclosure detected",
                path='/user/scripts/login_par.js',
            )
            return True
        return False

