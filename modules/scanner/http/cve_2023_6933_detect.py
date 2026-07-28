#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Better Search Replace plugin for WordPress is vulnerable to PHP Object Injection in all versions up to, an."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Better Search Replace < 1.4.5 - PHP Object Injection Detection',
        'description': 'The Better Search Replace plugin for WordPress is vulnerable to PHP Object Injection in all versions up to, and including, 1.4.4 via deserialization of untrusted input. This makes it possible for unauthenticated attackers to inject a PHP Object. No POP chain is present in the vulnerable plugin. If a POP chain is present via an additional plugin or theme installed on the target system, it could allow the attacker to delete arbitrary files, retrieve sensitive data, or execute code.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'wordpress', 'wp-plugin', 'wp', 'wpscan', 'better-search-replace', 'passive', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://posimyth.ticksy.com/ticket/2713734/',
            'https://www.wordfence.com/blog/2021/03/critical-0-day-in-the-plus-addons-for-elementor-allows-site-takeover/',
        ],
        'cve': 'CVE-2023-6933',
    }

    def run(self):
        for path in ('/wp-content/plugins/better-search-replace/README.txt', '/wp-content/plugins/better-search-replace/readme.txt'):
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('Better Search',)
            if any(m in body for m in body_any):
                self.set_info(
                    severity='critical',
                    reason='Better Search Replace < 1.4.5 - PHP Object Injection detected',
                    path=path,
                )
                return True
        return False

