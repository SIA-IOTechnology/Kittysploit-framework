#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""doorGets 7."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'DoorGets CMS v7.0 - Information Disclosure Detection',
        'description': "doorGets 7.0 has a sensitive information disclosure vulnerability in /setup/temp/admin.php. A remote unauthenticated attacker could exploit this vulnerability to obtain administrator's password.",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'doorgets', 'cms', 'packetstorm', 'disclosure', 'vuln'],
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
            'https://packetstormsecurity.com/files/174236/DoorGets-CMS-7.0-Information-Disclosure.html',
            'https://sourceforge.net/projects/doorgets-cms/files/latest/download?source=directory',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/v12/setup/temp/admin.php', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = (':"email";', ':"password";',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="DoorGets CMS v7.0 - Information Disclosure detected",
                path='/v12/setup/temp/admin.php',
            )
            return True
        return False

