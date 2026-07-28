#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects Slack Webhook URL."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Slack Webhook URL Detection',
        'description': 'Detects Slack Webhook URL.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'exposure', 'token', 'slack', 'vuln'],
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
            'https://github.com/semgrep/semgrep-rules/blob/develop/generic/secrets/gitleaks/slack-webhook-url.go',
            'https://github.com/semgrep/semgrep-rules/blob/develop/generic/secrets/gitleaks/slack-webhook-url.yaml',
            'https://api.slack.com/messaging/webhooks',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('https://hooks\\\\.slack\\\\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}', '(https?:\\/\\/)?hooks.slack.com\\/(services|workflows)\\/[A-Za-z0-9+\\/]{43,46}',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='info',
                reason="Slack Webhook URL detected",
                path='/',
            )
            return True
        return False

