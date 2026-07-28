#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Security vulnerability known as Unauthenticated access to settings or Unauthenticated configuration download."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'D-Link DAP-1325 - Information Disclosure Detection',
        'description': 'Security vulnerability known as Unauthenticated access to settings or Unauthenticated configuration download. This vulnerability occurs when a device, such as a repeater, allows the download of user settings without requiring proper authentication.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'misconfiguration', 'misconfig', 'config', 'dump', 'dlink', 'auth-bypass', 'disclosure', 'vuln'],
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
            'https://www.exploit-db.com/exploits/51556',
            'https://www.dropbox.com/s/eqz0ntlzqp5472l/DAP-1325.mp4?dl=0',
        ],
    }

    def run(self):
        return False  # disabled: corrupted matchers
        r = self.http_request(method="GET", path='/cgi-bin/ExportSettings.sh', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items()).lower()
        body_any = ('password',)
        header_regexes = ('filename="(.*)_Settings.dat', 'application/octet-stream',)
        if (any(m in body for m in body_any)) and (any(re.search(rx, headers, re.I) for rx in header_regexes)):
            self.set_info(
                severity='critical',
                reason="D-Link DAP-1325 - Information Disclosure detected",
                path='/cgi-bin/ExportSettings.sh',
            )
            return True
        return False

