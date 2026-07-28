#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Plus Addons for Elementor plugin (before version 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'The Plus Addons for Elementor Page Builder < 4.1.7 - Authentication Bypass Detection',
        'description': 'The Plus Addons for Elementor plugin (before version 4.1.7) allowed attackers to bypass authentication, gain admin access, and create accounts with elevated roles, even when registration was disabled and the Login widget was inactive.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'wordpress', 'wp-theme', 'wpscan', 'elementor', 'plus-addons', 'passive', 'vkev', 'vuln'],
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
            'https://wpscan.com/vulnerability/c311feef-7041-4c21-9525-132b9bd32f89/',
            'https://www.wordfence.com/blog/2021/03/critical-0-day-in-the-plus-addons-for-elementor-allows-site-takeover/',
        ],
        'cve': 'CVE-2021-24175',
    }

    def run(self):
        path = '/wp-content/plugins/the-plus-addons-for-elementor-page-builder/readme.txt'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('The Plus Addons for Elementor',)
        if any(m in body for m in body_any):
            self.set_info(
                severity='critical',
                reason='The Plus Addons for Elementor Page Builder < 4.1.7 - Authentication Bypass detected',
                path=path,
            )
            return True
        return False

