#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SpiderControl SCADA Web Server is vulnerable to sensitive information exposure."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SpiderControl SCADA Web Server - Sensitive Information Exposure Detection',
        'description': 'SpiderControl SCADA Web Server is vulnerable to sensitive information exposure. Numerous, market-leading OEM manufacturers - from a wide variety of industries - rely on SpiderControl.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'misconfiguration', 'spidercontrol', 'scada', 'exposure', 'misconfig', 'vuln'],
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
        'references': ['https://spidercontrol.net/spidercontrol-inside/'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/cgi-bin/GetSrvInfo.exe', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('powered by SpiderControl', 'LSWEBSERVER', 'SCWEBSERVICES',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="SpiderControl SCADA Web Server - Sensitive Information Exposure detected",
                path='/cgi-bin/GetSrvInfo.exe',
            )
            return True
        return False

