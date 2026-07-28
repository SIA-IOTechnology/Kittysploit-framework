#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detectes vulnerable compormised version of lottie-player JS Library that were compormised with a Web3 wallet p."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Lottie Player - Backdoor Detection',
        'description': 'Detectes vulnerable compormised version of lottie-player JS Library that were compormised with a Web3 wallet pop-up backdoor.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'vulnerability', 'cdn', 'lottie-player', 'backdoor', 'malware', 'vuln'],
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
            'https://github.com/LottieFiles/lottie-player/issues/254',
            'https://x.com/galnagli/status/1851779972639363076',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('lottie-player@2.0.5', 'lottie-player@2.0.6', 'lottie-player@2.0.7',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='critical',
                reason="Lottie Player - Backdoor detected",
                path='/',
            )
            return True
        return False

