#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ZTE panel was detected."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ZTE Panel - Detect',
        'description': 'ZTE panel was detected. ZTE Corporation is a global leader in telecommunications and information technology. Founded in 1985 and listed on both the Hong Kong and Shenzhen Stock Exchanges, the company has been committed to providing innovative technologies and integrated solutions for global operators, government and enterprise, and consumers from over 160 countries across the globe. ZTE Corporation is a global leader in telecommunications and information technology. Founded in 1985 and listed on both the Hong Kong and Shenzhen Stock Exchanges, the company has been committed to providing innovative technologies and integrated solutions for global operators, government and enterprise, and consumers from over 160 countries across the globe.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'zte'],
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
        'references': ['https://www.zte.com.cn/global/'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_markers = (
            'ZTE Corporation. All rights reserved. </div>',
            '<form name="fLogin" id="fLogin" method="post"  onsubmit="return false;" action="">',
        )
        body_hit = any(m in body for m in body_markers)
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_markers = (
            'Mini web server 1.0 ZTE corp 2005.',
        )
        if body_hit and any(m in headers for m in header_markers):
            self.set_info(
                severity='info',
                reason="ZTE Panel detected",
                path='/',
            )
            return True
        return False

