#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Adning Advertising plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type v."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Adning Advertising <= 1.5.5 - Arbitrary File Upload Detection',
        'description': 'The Adning Advertising plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the _ning_upload_image function in versions up to, and including, 1.5.5. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected sites server which may make remote code execution possible.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'wordpress', 'wp-plugin', 'angwp', 'wp', 'passive', 'vkev', 'vuln'],
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
            'https://blog.nintechnet.com/critical-vulnerability-in-adning-advertising-plugin-actively-exploited-in-the-wild/',
            'https://codecanyon.net/item/wp-pro-advertising-system-all-in-one-ad-manager/269693',
            'https://wpscan.com/vulnerability/e9873fe3-fc06-4a52-aa32-6922cab7830c',
            'https://www.wordfence.com/threat-intel/vulnerabilities/id/4a263b74-e9ae-4fd2-be9b-9b8e9eee5982?source=cve',
        ],
        'cve': 'CVE-2020-36705',
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('served by Adning', 'adning.com',)
        if all(m in body for m in body_all):
            self.set_info(
                severity='critical',
                reason='Adning Advertising <= 1.5.5 - Arbitrary File Upload detected',
                path=path,
            )
            return True
        return False

