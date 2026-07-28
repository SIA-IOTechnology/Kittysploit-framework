#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Comtrend ADSL CT-5367 C01_R12 router is susceptible to remote code execution."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Comtrend ADSL - Remote Code Execution Detection',
        'description': 'Comtrend ADSL CT-5367 C01_R12 router is susceptible to remote code execution. A remote user can execute arbitrary commands via the telnet interface, The password for this interface is leaked to unauthenticated users via the password.cgi endpoint.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'router', 'exposure', 'iot', 'rce', 'edb', 'vuln'],
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
        'references': ['https://www.exploit-db.com/exploits/16275'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/password.cgi', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('pwdAdmin =', 'pwdSupport =', 'pwdUser =',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="Comtrend ADSL - Remote Code Execution detected",
                path='/password.cgi',
            )
            return True
        return False

