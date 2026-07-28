#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Magento Mass Importer (aka MAGMI) versions prior to 0."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Magento Mass Importer  <0.7.24 - Remote Auth Bypass Detection',
        'description': 'Magento Mass Importer (aka MAGMI) versions prior to 0.7.24 are vulnerable to a remote authentication bypass due to allowing default credentials in the event there is a database connection failure.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'plugin', 'tenable', 'magmi', 'magento', 'auth', 'bypass', 'magmi_project', 'vuln'],
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
            'https://github.com/dweeves/magmi-git/blob/18bd9ec905c90bfc9eaed0c2bf2d3525002e33b9/magmi/inc/magmi_auth.php#L35',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-5777',
            'https://www.tenable.com/security/research/tra-2020-51',
            'https://github.com/404notf0und/CVE-Flow',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2020-5777',
    }

    def run(self):
        path = '/index.php/catalogsearch/advanced/result/?name=e'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Connection': 'close'})
        if not r or r.status_code != 503:
            return False
        body = r.text or ""
        body_any = ('Too many connections',)
        if any(m in body for m in body_any):
            self.set_info(severity='critical', reason='Magento Mass Importer  <0.7.24 - Remote Auth Bypass detected', path=path)
            return True
        return False

