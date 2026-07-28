#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""LimeSurvey before 6."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'LimeSurvey - Open Redirect via editorLink Detection',
        'description': 'LimeSurvey before 6.16.11 contains an open redirect vulnerability in the editorLink route. An attacker can craft a URL that redirects users to an arbitrary external site, potentially enabling phishing attacks.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'vulnerability', 'limesurvey', 'redirect', 'vuln'],
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
        'references': ['https://github.com/LimeSurvey/LimeSurvey/pull/4727'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/index.php?r=editorLink&url=http://interact.sh/', allow_redirects=False)
        if not r or r.status_code != 302:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('LS_AUTH_INIT',)
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?://|//)(?:[a-zA-Z0-9\\-_\\.@]*)interact\\.sh.*$',)
        if (any(m in headers for m in header_any)) and (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="LimeSurvey - Open Redirect via editorLink detected",
                path='/index.php?r=editorLink&url=http://interact.sh/',
            )
            return True
        return False

