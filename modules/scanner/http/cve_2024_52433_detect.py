#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The My Geo Posts Free plugin for WordPress is vulnerable to PHP Object Injection in versions up to, and includ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'My Geo Posts Free <= 1.2 - PHP Object Injection Detection',
        'description': 'The My Geo Posts Free plugin for WordPress is vulnerable to PHP Object Injection in versions up to, and including, 1.2 via deserialization of untrusted input. This makes it possible for unauthenticated attackers to inject a PHP Object. No known POP chain is present in the vulnerable software. If a POP chain is present via an additional plugin or theme installed on the target system, it could allow the attacker to delete arbitrary files, retrieve sensitive data, or execute code.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'wordpress', 'wp', 'wp-plugin', 'my-geo-posts-free', 'php', 'injection', 'vuln'],
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
            'https://github.com/RandomRobbieBF/CVE-2024-52433',
            'https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/my-geo-posts-free/my-geo-posts-free-12-unauthenticated-php-object-injection',
            'https://patchstack.com/database/vulnerability/my-geo-posts-free/wordpress-my-geo-posts-free-plugin-1-2-php-object-injection-vulnerability?_s_id=cve',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-52433',
        ],
        'cve': 'CVE-2024-52433',
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Warning', 'mgpf_get_geo_location()', '{{encrypt}}',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='critical',
                reason="My Geo Posts Free <= 1.2 - PHP Object Injection detected",
                path='/',
            )
            return True
        return False

