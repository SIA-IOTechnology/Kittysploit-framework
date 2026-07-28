#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Vito Peleg Atarim <= 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Atarim < 4.2.2 - Sensitive Information Exposure Detection',
        'description': 'Vito Peleg Atarim <= 4.2 contains an insertion of sensitive information into sent data vulnerability caused by improper handling of embedded sensitive data, letting attackers retrieve embedded sensitive data remotely, exploit requires no special privileges.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'modules': [
            'auxiliary/admin/http/wp_plugin_atarim_cve_2025_60188',
        ],
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'wordpress', 'wp-plugin', 'atarim', 'exposure'],
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
        'references': ['https://github.com/m4sh-wacker/CVE-2025-60188-Atarim-Plugin-Exploit'],
        'cve': 'CVE-2025-60188',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-json/atarim/v1/db/vc', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('"wpf_site_id":"', '"notify_user":',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='high',
                reason="Atarim < 4.2.2 - Sensitive Information Exposure detected",
                path='/wp-json/atarim/v1/db/vc',
            )
            return True
        return False

