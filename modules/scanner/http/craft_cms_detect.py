#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects Craft CMS."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Craft CMS Detect',
        'description': 'Detects Craft CMS',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'technology', 'tech', 'craftcms'],
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
        'references': ['https://craftcms.com'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('(?i)CRAFT_CSRF_TOKEN',)
        body_re_hit = any(re.search(rx, body, 0) for rx in body_regexes)
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_markers = ('X-Powered-By: Craft CMS',)
        header_word_hit = any(m in headers for m in header_markers)
        header_regexes = ('Set-Cookie: (Craft|CRAFT)',)
        header_re_hit = any(re.search(rx, headers, 0) for rx in header_regexes)
        if body_re_hit or header_word_hit or header_re_hit:
            self.set_info(
                severity='info',
                reason="Craft CMS detected",
                path='/',
            )
            return True
        return False

