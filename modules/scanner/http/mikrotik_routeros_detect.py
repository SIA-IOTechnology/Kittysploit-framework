#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MikroTik Router OS login panel was detected."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'MikroTik Router OS Login Panel - Detect',
        'description': 'MikroTik Router OS login panel was detected.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'login', 'mikrotik'],
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
            'https://systemweakness.com/routeros-user-with-just-ftp-policy-can-write-to-filesystem-cve-2021-27221-e3e45d780dfe',
        ],
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('<title>mikrotik routeros > administration</title>', '<title>Mikrotik Router', '<img src="/webcfg/', '<title>MikroTik RouterOS Managing Webpage</title>',)
        body_all = ('If this device is not in your possession, please contact your local network administrator', '.mikrotik.com', 'Please log on to use the mikrotik hotspot service', 'mikrotik hotspot > login',)
        header_any = ('Server: mikrotik httpproxy',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='info',
                reason='MikroTik Router OS Login Panel detected',
                path=path,
            )
            return True
        return False

