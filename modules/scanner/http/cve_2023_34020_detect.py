#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A vulnerability in the WordPress Uncanny Toolkit for LearnDash Plugin allowed malicious actors to redirect use."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Uncanny Toolkit for LearnDash - Open Redirection Detection',
        'description': 'A vulnerability in the WordPress Uncanny Toolkit for LearnDash Plugin allowed malicious actors to redirect users, posing a potential risk of phishing incidents. The issue has been resolved in version 3.6.4.4, and users are urged to update for security.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'wordpress', 'uncanny-learndash-toolkit', 'wpscan', 'redirect', 'vuln'],
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
            'https://patchstack.com/database/vulnerability/uncanny-learndash-toolkit/wordpress-uncanny-toolkit-for-learndash-plugin-3-6-4-3-open-redirection-vulnerability',
            'https://wordpress.org/plugins/uncanny-learndash-toolkit/',
            'https://patchstack.com/database/vulnerability/uncanny-learndash-toolkit/wordpress-uncanny-toolkit-for-learndash-plugin-3-6-4-3-open-redirection-vulnerability?_s_id=cve',
        ],
        'cve': 'CVE-2023-34020',
    }

    def run(self):
        r = self.http_request(method="GET", path='/?rest_route=/ult/v2/review-banner-visibility&action=maybe-later&redirect=yes&redirect_url=https://interact.sh', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?:\\/\\/|\\/\\/|\\/\\\\\\\\|\\/\\\\)(?:[a-zA-Z0-9\\-_\\.@]*)interact\\.sh\\/?(\\/|[^.].*)?$',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="Uncanny Toolkit for LearnDash - Open Redirection detected",
                path='/?rest_route=/ult/v2/review-banner-visibility&action=maybe-later&redirect=yes&redirect_url=https://interact.sh',
            )
            return True
        return False

