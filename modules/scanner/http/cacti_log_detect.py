#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Exposed Cacti log files (cacti."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Cacti Log - Exposure Detection',
        'description': 'Exposed Cacti log files (cacti.log) were detected. These files contain system statistics, error messages, and potentially sensitive information. They can also be used in log poisoning attacks.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'exposure', 'cacti', 'log', 'file'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 4,
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
        'references': ['https://docs.cacti.net/Cacti-Log.md'],
    }

    def run(self):
        for path in ('/cacti/log/cacti.log', '/log/cacti.log', '/cacti.log', '/include/cacti.log'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('SYSTEM STATS', 'Method:', 'Processes:', 'Threads:', 'Hosts:',)
            body_regexes = ('(?i)SYSTEM STATS: Time:', '(?i)POLLER: Poller\\[', '(?i)Cacti\\[[0-9]+\\]', '(?i)CMDPHP:',)
            if (all(m in body for m in body_all)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
                self.set_info(
                    severity='medium',
                    reason="Cacti Log - Exposure detected",
                    path=path,
                )
                return True
        return False

