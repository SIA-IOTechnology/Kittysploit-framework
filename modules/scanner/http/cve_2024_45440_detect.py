#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""core/authorize."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Drupal 11.x-dev - Full Path Disclosure Detection',
        'description': 'core/authorize.php in Drupal 11.x-dev allows Full Path Disclosure (even when error logging is None) if the value of hash_salt is file_get_contents of a file that does not exist.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'drupal', 'exposure', 'error', 'vuln'],
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
            'https://senscybersecurity.nl/CVE-2024-45440-Explained/',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-45440',
        ],
        'cve': 'CVE-2024-45440',
    }

    def run(self):
        r = self.http_request(method="GET", path='/core/authorize.php', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('getHashSalt', 'RuntimeException',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="Drupal 11.x-dev - Full Path Disclosure detected",
                path='/core/authorize.php',
            )
            return True
        return False

