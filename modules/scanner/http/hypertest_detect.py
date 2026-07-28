#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HyperTest Common Dashboard was detected."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'HyperTest Common Dashboard - Detect',
        'description': 'HyperTest Common Dashboard was detected.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'exposure', 'hypertest'],
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
            'https://www.facebook.com/photo?fbid=487809593389565&set=a.467014098802448',
            'https://www.hypertest.co',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/dashboard/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_markers = (
            '<title>HyperTest | Common Dashboard</title>',
            'HyperTest | Dashboard',
            "HyperTest doesn't work",
        )
        body_hit = any(m in body for m in body_markers)
        if body_hit:
            self.set_info(
                severity='info',
                reason="HyperTest Common Dashboard detected",
                path='/dashboard/',
            )
            return True
        return False

