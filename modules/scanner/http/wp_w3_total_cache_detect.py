#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects publicly accessible W3 Total Cache database cache files in the wp-content/w3tc/dbcache/ directory."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress W3 Total Cache - Cache Files Exposure Detection',
        'description': 'Detects publicly accessible W3 Total Cache database cache files in the wp-content/w3tc/dbcache/ directory. When database caching to disk is enabled, these files contain raw SQL query results, potentially exposing sensitive data such as user details, password hashes, emails, or other database content if the directory is not properly protected.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'exposure', 'wordpress', 'wp-plugin', 'w3-total-cache', 'cache', 'misconfig'],
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
            'https://www.acunetix.com/vulnerabilities/web/wordpress-w3-total-cache-plugin-predictable-cache-filenames/',
            'https://www.openwall.com/lists/oss-security/2012/12/30/3 (CVE-2012-6077 related discussion)',
            'https://siteground.com/blog/w3-total-cache-vulnerability/',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/w3tc/dbcache/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('wp-content/w3tc/dbcache', 'Index of', 'Parent Directory',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="WordPress W3 Total Cache - Cache Files Exposure detected",
                path='/wp-content/w3tc/dbcache/',
            )
            return True
        return False

