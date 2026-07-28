#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Frontend Post Submission Manager Lite plugin for WordPress is vulnerable to Open Redirection in all versio."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Frontend Post Submission Manager Lite <= 1.2.7 - Open Redirect Detection',
        'description': "The Frontend Post Submission Manager Lite plugin for WordPress is vulnerable to Open Redirection in all versions up to, and including, 1.2.7 due to insufficient validation on the 'requested_page' POST parameter in the verify_username_password function. This makes it possible for unauthenticated attackers to redirect users to potentially malicious sites if they can successfully trick them into performing an action such as clicking on a link.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2026', 'wordpress', 'wp', 'wp-plugin', 'redirect', 'frontend-post-submission-manager-lite'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/frontend-post-submission-manager-lite/frontend-post-submission-manager-lite-127-unauthenticated-open-redirect-via-requested-page-parameter',
            'http://nvd.nist.gov/vuln/detail/CVE-2026-1296',
        ],
        'cve': 'CVE-2026-1296',
    }

    def run(self):
        path = '/wp-login.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='log=&pwd=&wp-submit=Log+In&action=login&requested_page=https://oast.pro\n')
        if not r or r.status_code != 302:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?:\\/\\/|\\/\\/|\\/\\\\\\\\|\\/\\\\)(?:[a-zA-Z0-9\\-_\\.@]*)oast\\.pro\\/?(\\/|[^.].*)?$',)
        if any(re.search(rx, headers) for rx in header_regexes):
            self.set_info(severity='medium', reason='Frontend Post Submission Manager Lite <= 1.2.7 - Open Redirect detected', path=path)
            return True
        return False

