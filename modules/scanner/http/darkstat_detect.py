#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Darkstat captures network traffic, calculates statistics about usage, and serves reports over HTTP."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Detect Darkstat Reports',
        'description': 'Darkstat captures network traffic, calculates statistics about usage, and serves reports over HTTP',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'exposure', 'darkstat', 'logs'],
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
        'references': ['https://unix4lyfe.org/darkstat/'],
    }

    def run(self):
        for path in ('/', '/darkstat/'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_all = ('darkstat', '<title>Graphs', 'Measuring for', 'hosts</a>',)
            header_regexes = ('[Ss]erver: darkstat.*',)
            if (all(m in body for m in body_all)) and (any(re.search(rx, headers, 0) for rx in header_regexes)):
                self.set_info(
                    severity='high',
                    reason="Detect Darkstat Reports detected",
                    path=path,
                )
                return True
        return False

