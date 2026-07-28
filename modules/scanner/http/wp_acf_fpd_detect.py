#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Advanced Custom Fields (ACF) for WordPress contains a full path disclosure vulnerability due to improper acces."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Advanced Custom Fields (ACF) - Full Path Disclosure Detection',
        'description': 'Advanced Custom Fields (ACF) for WordPress contains a full path disclosure vulnerability due to improper access restrictions in its source files, allowing unauthenticated attackers to retrieve full server paths and aiding exploitation.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'misconfiguration', 'debug', 'wordpress', 'wp', 'wp-plugin', 'acf', 'fpd'],
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
        'references': ['https://www.advancedcustomfields.com'],
    }

    def run(self):
        path = '/wp-content/plugins/advanced-custom-fields/includes/fields/class-acf-field-accordion.php'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        ctype_any = ('text/html',)
        body_regexes = ('/[a-zA-Z0-9_\\-/]+/wp-content/plugins/advanced-custom-fields/includes/fields/class-acf-field-accordion\\.php',)
        if (any(m in content_type for m in ctype_any)) and (any(re.search(rx, body) for rx in body_regexes)):
            self.set_info(
                severity='low',
                reason='Advanced Custom Fields (ACF) - Full Path Disclosure detected',
                path=path,
            )
            return True
        return False

