#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""An unauthenticated exposed web interface for Siemens SIMATIC S7-300 was discovered, potentially allowing acces."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Siemens SIMATIC 300 Dashboard - Exposed Detection',
        'description': 'An unauthenticated exposed web interface for Siemens SIMATIC S7-300 was discovered, potentially allowing access without any login credentials.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'misconfiguration', 'siemens', 'simatic', 'plc', 'scada', 'iot', 'misconfig', 'unauth', 'vuln'],
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
        'references': ['https://new.siemens.com'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/Portal0000.htm', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('alt="Simatic S7 CP"',)
        body_regexes = ('SIMATIC\\s*300',)
        if (any(m in body for m in body_any)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Siemens SIMATIC 300 Dashboard - Exposed detected",
                path='/Portal0000.htm',
            )
            return True
        return False

