#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Exposed Kong Manager (OSS/Admin) interface accessible without authentication."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Kong Manager OSS/Admin - Exposure Detection',
        'description': 'Exposed Kong Manager (OSS/Admin) interface accessible without authentication.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'panel', 'kong', 'manager', 'misconfig', 'exposure'],
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
        'references': ['http://github.com/Kong/kong-manager'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        # Do NOT match generic HTML — routers/soft pages caused FPs via 'text/html'.
        strong = (
            "Kong Manager OSS",
            "Kong Manager",
            "Kong Admin",
            "window.K_CONFIG",
            "kong-admin-ui",
        )
        if any(m in body for m in strong):
            self.set_info(
                severity="medium",
                reason="Kong Manager OSS/Admin - Exposure detected",
                path="/",
            )
            return True
        # Secondary: kconfig.js reference only when Kong context is also present.
        if "kconfig.js" in body and "kong" in body.lower():
            self.set_info(
                severity="medium",
                reason="Kong Manager OSS/Admin - Exposure detected",
                path="/",
            )
            return True
        return False

