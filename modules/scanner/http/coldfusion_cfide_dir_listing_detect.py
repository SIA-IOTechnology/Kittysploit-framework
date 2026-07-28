#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected Adobe ColdFusion CFIDE directory listing was exposed."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Adobe ColdFusion CFIDE - Directory Listing Detection',
        'description': 'Detected Adobe ColdFusion CFIDE directory listing was exposed. This can reveal sensitive files and subdirectories including administrator interfaces, scripts, and application components.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'misconfiguration', 'misconfig', 'coldfusion', 'adobe', 'exposure', 'listing'],
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
            'https://helpx.adobe.com/coldfusion/kb/securing-coldfusion.html',
            'https://www.carnal0wnage.com/papers/LARES-ColdFusion.pdf',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/CFIDE/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('administrator', 'scripts', 'componentutils', 'wizards', 'adminapi',)
        body_all = ('Index of', 'CFIDE',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="Adobe ColdFusion CFIDE - Directory Listing detected",
                path='/CFIDE/',
            )
            return True
        return False

