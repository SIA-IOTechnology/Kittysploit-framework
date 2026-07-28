#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Solar-Log 500 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Solar-Log 500 2.8.2 - Incorrect Access Control Detection',
        'description': 'Solar-Log 500 2.8.2 is susceptible to incorrect access control because the web administration server for Solar-Log 500 all versions prior to 2.8.2 Build 52 does not require authentication, which allows arbitrary remote attackers gain administrative privileges by connecting to the server.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'solarlog', 'auth-bypass', 'edb', 'vuln'],
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
        'references': ['https://www.exploit-db.com/exploits/49986'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/lan.html', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('Solare Datensysteme GmbH', 'mailto:info@solar-log.com',)
        header_any = ('IPC@CHIP',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="Solar-Log 500 2.8.2 - Incorrect Access Control detected",
                path='/lan.html',
            )
            return True
        return False

