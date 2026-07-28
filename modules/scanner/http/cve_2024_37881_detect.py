#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The SiteGuard WP Plugin plugin for WordPress is vulnerable to protection mechanism bypass in all versions up t."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SiteGuard WP Plugin <= 1.7.6 - Login Page Disclosure Detection',
        'description': 'The SiteGuard WP Plugin plugin for WordPress is vulnerable to protection mechanism bypass in all versions up to, and including, 1.7.6. This is due to the plugin not restricting redirects from wp-register.php which may disclose the login page URL. This makes it possible for unauthenticated attackers to gain access to the login page.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'siteguard', 'wp-plugin', 'vuln'],
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
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': [
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-37881',
            'https://jvn.jp/en/jp/JVN60331535/',
            'https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/siteguard/siteguard-wp-plugin-176-login-page-disclosure',
            'https://www.usom.gov.tr/bildirim/tr-24-0726',
        ],
        'cve': 'CVE-2024-37881',
    }

    def run(self):
        for path in ('/wp-content/plugins/siteguard/readme.txt', '/wp-register.php'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = (r.text or "").lower()
            body_any = ('siteguard wp plugin', 'wp-login.php', 'wp-register.php', 'notfound', 'not-found', '/404',)
            if (any(m in body for m in body_any)):
                self.set_info(
                    severity='medium',
                    reason="SiteGuard WP Plugin <= 1.7.6 - Login Page Disclosure detected",
                    path=path,
                )
                return True
        return False

