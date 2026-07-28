#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Uptime-Kuma before v1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Uptime-Kuma < v1.23.0 - Improper Access Control Detection',
        'description': 'Uptime-Kuma before v1.23.0 is vulnerable to an information disclosure issue due to missing authorization on the /api/badge/1/ping/24 endpoint. An unauthenticated attacker can access this endpoint to leak ping statistics, such as average ping and ping history, for existing monitors without needing access to the protected status page. This can lead to unintended exposure of internal monitoring data.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2026', 'uptime-kuma', 'exposure'],
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
            'https://github.com/advisories/GHSA-c7hf-c5p5-5g6h',
            'https://nvd.nist.gov/vuln/detail/CVE-2026-32230',
        ],
        'cve': 'CVE-2026-32230',
    }

    def run(self):
        r = self.http_request(method="GET", path='/api/badge/1/ping/24', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Avg. Ping (',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='medium',
                reason="Uptime-Kuma < v1.23.0 - Improper Access Control detected",
                path='/api/badge/1/ping/24',
            )
            return True
        return False

