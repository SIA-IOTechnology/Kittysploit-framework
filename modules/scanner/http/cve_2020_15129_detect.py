#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Traefik before 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Traefik - Open Redirect Detection',
        'description': 'Traefik before 1.7.26, 2.2.8, and 2.3.0-rc3 contains an open redirect vulnerability in the X-Forwarded-Prefix header. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'traefik', 'redirect', 'vuln'],
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
            'https://securitylab.github.com/advisories/GHSL-2020-140-Containous-Traefik',
            'https://github.com/containous/traefik/releases/tag/v2.2.8',
            'https://github.com/containous/traefik/pull/7109',
            'https://github.com/containous/traefik/security/advisories/GHSA-6qq8-5wq3-86rp',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-15129',
        ],
        'cve': 'CVE-2020-15129',
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=False)
        if not r or r.status_code != 302:
            return False
        body = r.text or ""
        body_any = ('<a href="https://foo.nl/dashboard/">Found</a>',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='medium',
                reason="Traefik - Open Redirect detected",
                path='/',
            )
            return True
        return False

