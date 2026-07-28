#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Moodle has a file which describes API changes in core libraries and APIs, and can be used to discover Moodle v."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Moodle Changelog File Detect',
        'description': 'Moodle has a file which describes API changes in core libraries and APIs, and can be used to discover Moodle version.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'misc', 'moodle', 'exposure', 'vuln'],
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
            'https://moodledev.io/general/development/upgradenotes',
            'https://moodle.atlassian.net/browse/MDL-81125',
            'https://github.com/moodle/moodle',
        ],
    }

    def run(self):
        for path in ('/lib/upgrade.txt', '/UPGRADING.md'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = (r.text or "").lower()
            body_any = ('text/plain', 'this files describes api changes', 'text/', 'developer update notes',)
            if (any(m in body for m in body_any)):
                self.set_info(
                    severity='info',
                    reason="Moodle Changelog File detected",
                    path=path,
                )
                return True
        return False

