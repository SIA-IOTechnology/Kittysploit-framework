#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ICEFlow VPN internal log file is exposed."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ICEFlow VPN Disclosure Detection',
        'description': 'ICEFlow VPN internal log file is exposed.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'exposure', 'files', 'iceflow', 'logs', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 6,
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
    }

    def run(self):
        for path in ('/log/system.log', '/log/vpn.log', '/log/access.log', '/log/warn.log', '/log/error.log', '/log/debug.log', '/log/mobile.log', '/log/firewall.log'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_any = ('ICEFLOW VPN:', 'ICEFLOW SYSTEM', 'ICEFLOW',)
            header_all = ('text/plain', 'ICEFLOW',)
            if (any(m in body for m in body_any)) and (all(m in headers for m in header_all)):
                self.set_info(
                    severity='low',
                    reason="ICEFlow VPN Disclosure detected",
                    path=path,
                )
                return True
        return False

