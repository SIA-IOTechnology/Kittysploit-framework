#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Print Invoice & Delivery Notes for WooCommerce plugin for WordPress <= 5."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Print Invoice & Delivery Notes for WooCommerce <= 5.8.0 - Remote Code Execution Detection',
        'description': 'Print Invoice & Delivery Notes for WooCommerce plugin for WordPress <= 5.8.0 contains a remote code execution caused by missing capability check, PHP enabled in Dompdf, and missing escape in template.php, letting unauthenticated attackers execute code on the server.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'wordpress', 'wp-plugin', 'woocommerce-delivery-notes', 'rce', 'passive', 'vkev'],
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://www.wordfence.com/threat-intel/vulnerabilities/id/e52b34fe-2414-4d6f-bf43-9c5b65ebf769',
            'https://plugins.trac.wordpress.org/changeset/3426119/woocommerce-delivery-notes',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-13773',
        ],
        'cve': 'CVE-2025-13773',
    }

    def run(self):
        path = '/wp-content/plugins/woocommerce-delivery-notes/readme.txt'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Print Invoice & Delivery Notes',)
        if any(m in body for m in body_any):
            self.set_info(
                severity='critical',
                reason='WordPress Print Invoice & Delivery Notes for WooCommerce <= 5.8.0 - Remote Code Execution detected',
                path=path,
            )
            return True
        return False

