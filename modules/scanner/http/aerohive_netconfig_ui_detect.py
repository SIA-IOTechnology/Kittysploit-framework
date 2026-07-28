#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""An Aerohive NetConfig user interface was detected."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Aerohive NetConfig UI Detection',
        'description': 'An Aerohive NetConfig user interface was detected. The NetConfig UI provides a fundamental set of configurations for configuring basic network and HiveManager connectivity settings, and uploading new IQ Engine images to Extreme Networks APs.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'tech', 'hiveos', 'aerohive'],
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
            'https://docs.aerohive.com/330000/docs/help/english/ng/Content/reference/docs/online-help-systems.htm',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/index.php5', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_markers = (
            '<title>Aerohive NetConfig UI</title>',
        )
        if any(m in body for m in body_markers):
            self.set_info(
                severity='info',
                reason="Aerohive NetConfig UI detected",
                path='/index.php5',
            )
            return True
        return False

