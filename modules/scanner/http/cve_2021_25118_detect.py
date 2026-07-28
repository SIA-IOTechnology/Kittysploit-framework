#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Yoast SEO plugin 16."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Yoast SEO 16.7-17.2 - Information Disclosure Detection',
        'description': 'Yoast SEO plugin 16.7 to 17.2 is susceptible to information disclosure, The plugin discloses the full internal path of featured images in posts via the wp/v2/posts REST endpoints, which can help an attacker identify other vulnerabilities or help during the exploitation of other identified vulnerabilities.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'wpscan', 'wordpress', 'wp-plugin', 'fpd', 'wp', 'yoast', 'vuln'],
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
            'https://wpscan.com/vulnerability/2c3f9038-632d-40ef-a099-6ea202efb550',
            'https://plugins.trac.wordpress.org/changeset/2608691',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-25118',
            'https://github.com/20142995/sectool',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2021-25118',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-json/wp/v2/posts?per_page=1', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('application/json',)
        body_regexes = ('"path":"(.*)/wp-content\\\\(.*)","size',)
        if (any(m in headers for m in header_any)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='medium',
                reason="Yoast SEO 16.7-17.2 - Information Disclosure detected",
                path='/wp-json/wp/v2/posts?per_page=1',
            )
            return True
        return False

