#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The GitHub repository mastodon/mastodon prior to 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Mastodon Prototype Pollution Vulnerability Detection',
        'description': 'The GitHub repository mastodon/mastodon prior to 3.5.0 contains a Prototype Pollution vulnerability.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'mastodon', 'prototype', 'huntr', 'joinmastodon', 'vuln'],
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
            'https://github.com/mastodon/mastodon/commit/4d6d4b43c6186a13e67b92eaf70fe1b70ea24a09',
            'https://drive.google.com/file/d/1vpZ0CcmFhTEUasLTPUBf8o-4l7G6ojtG/view',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-0432',
            'https://huntr.dev/bounties/d06da292-7716-4d74-a129-dd04773398d7',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2022-0432',
    }

    def run(self):
        r = self.http_request(method="GET", path='/embed.js', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ("if (data.type !== 'setHeight' || !iframes[data.id]) {",)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='medium',
                reason="Mastodon Prototype Pollution Vulnerability detected",
                path='/embed.js',
            )
            return True
        return False

