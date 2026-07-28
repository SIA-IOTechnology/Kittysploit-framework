#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected exposed OpenCart error log files that may contain sensitive information including file paths, databas."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'OpenCart Error Log Disclosure Detection',
        'description': 'Detected exposed OpenCart error log files that may contain sensitive information including file paths, database errors, PHP warnings, and internal application details.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'exposure', 'opencart', 'logs', 'disclosure'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 5,
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
        'references': ['https://www.opencart.com/', 'https://docs.opencart.com/en-gb/administration/'],
    }

    def run(self):
        for path in ('/system/storage/logs/error.log', '/opencart/system/storage/logs/error.log', '/storage/logs/error.log', '/error.log', '/system/logs/error.log'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('PHP Notice', 'PHP Warning', 'PHP Error', 'PHP Fatal error', 'opencart', 'catalog/controller', 'catalog/model', 'system/library', 'Undefined index', 'MySQL', 'mysqli',)
            body_regexes = ('\\d{4}-\\d{2}-\\d{2}\\s+\\d{2}:\\d{2}:\\d{2}', '\\[error\\]|\\[warning\\]|\\[notice\\]',)
            if (any(m in body for m in body_any)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
                self.set_info(
                    severity='medium',
                    reason="OpenCart Error Log Disclosure detected",
                    path=path,
                )
                return True
        return False

