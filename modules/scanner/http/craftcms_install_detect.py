#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected Craft CMS installation wizard was exposed, allowing attackers to complete the installation process an."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Craft CMS Installation Wizard Exposure Detection',
        'description': 'Detected Craft CMS installation wizard was exposed, allowing attackers to complete the installation process and gain administrative access to the CMS.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'misconfiguration', 'craftcms', 'install', 'exposure', 'misconfig'],
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
            'https://craftcms.com/docs/4.x/installation.html',
            'https://craftcms.com/knowledge-base/securing-craft',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/admin/install', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('Install Craft', 'Create your account', '/cpresources/',)
        header_any = ('CRAFT_CSRF_TOKEN',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="Craft CMS Installation Wizard Exposure detected",
                path='/admin/install',
            )
            return True
        return False

