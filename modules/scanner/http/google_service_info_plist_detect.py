#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The GoogleService-Info."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'GoogleService-Info.plist - Detect',
        'description': 'The GoogleService-Info.plist file contains sensitive information about the Firebase project, including the Google App ID, Project ID, Client ID, Client Secret, and Reversed Client ID. This file is used to authenticate the Firebase SDK in iOS applications.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'exposure', 'config', 'firebase', 'ios'],
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
        'references': ['https://firebase.google.com/docs/ios/setup'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/GoogleService-Info.plist', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('application/octet-stream',)
        body_all = ('<key>GOOGLE_APP_ID</key>', '<key>PROJECT_ID</key>', '<key>API_KEY</key>',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='info',
                reason="GoogleService-Info.plist detected",
                path='/GoogleService-Info.plist',
            )
            return True
        return False

