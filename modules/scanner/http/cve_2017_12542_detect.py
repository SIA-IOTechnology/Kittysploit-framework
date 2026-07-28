#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HPE Integrated Lights-out 4 (iLO 4) prior to 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'HPE Integrated Lights-out 4 (ILO4) <2.53 - Authentication Bypass Detection',
        'description': 'HPE Integrated Lights-out 4 (iLO 4) prior to 2.53 was found to contain an authentication bypass and code execution vulnerability.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2017', 'ilo4', 'hpe', 'auth-bypass', 'edb', 'hp', 'vkev', 'vuln'],
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
            'https://www.exploit-db.com/exploits/44005',
            'https://nvd.nist.gov/vuln/detail/CVE-2017-12542',
            'https://support.hpe.com/hpsc/doc/public/display?docId=emr_na-hpesbhf03769en_us',
            'https://www.exploit-db.com/exploits/44005/',
            'http://www.securitytracker.com/id/1039222',
        ],
        'cve': 'CVE-2017-12542',
    }

    def run(self):
        r = self.http_request(method="GET", path='/rest/v1/AccountService/Accounts', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('iLO User',)
        header_any = ('application/json',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='critical',
                reason="HPE Integrated Lights-out 4 (ILO4) <2.53 - Authentication Bypass detected",
                path='/rest/v1/AccountService/Accounts',
            )
            return True
        return False

