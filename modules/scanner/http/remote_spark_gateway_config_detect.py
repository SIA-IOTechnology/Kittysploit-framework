#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Remote Spark Gateway config found via /gateway."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Remote Spark Gateway Configuration/Credentials - Exposure Detection',
        'description': 'Remote Spark Gateway config found via /gateway.conf.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'exposure', 'config', 'remote-spark'],
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
        'references': ['https://docs.sparkview.info/books/sparkview-admin-manual/page/31-gateway'],
    }

    def run(self):
        path = '/gateway.conf'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        content_type = (r.headers.get("Content-Type") or r.headers.get("content-type") or "").lower()
        body_all = ('<html', '<body',)
        ctype_any = ('text/plain',)
        body_regexes = ('credSSP\\s*=\\s*', 'html\\s*=\\s*', 'port\\s*=\\s*', 'password\\s*=\\s*',)
        if (all(m in body for m in body_all)) and (any(m in content_type for m in ctype_any)) and (any(re.search(rx, body, re.I) for rx in body_regexes)):
            self.set_info(
                severity='medium',
                reason='Remote Spark Gateway Configuration/Credentials - Exposure detected',
                path=path,
            )
            return True
        return False

