#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected Open redirect vulnerability in Jira via os_destination parameter versions 5."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'JIRA in HTTPS mode - Open Redirect Detection',
        'description': 'Detected Open redirect vulnerability in Jira via os_destination parameter versions 5.2.11, 6.2, and 6.2.2.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'vulnerability', 'confluence', 'atlassian', 'jira', 'redirect', 'vuln'],
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
        'references': ['https://jira.atlassian.com/browse/JRASERVER-38075'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/ThisCanBeAnything?os_destination=%2F%2Foast.pro', allow_redirects=False)
        if not r or r.status_code != 302:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*)(?:https?://|//|/\\\\\\\\)?[a-zA-Z0-9._@-]*oast\\.pro.*$',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="JIRA in HTTPS mode - Open Redirect detected",
                path='/ThisCanBeAnything?os_destination=%2F%2Foast.pro',
            )
            return True
        return False

