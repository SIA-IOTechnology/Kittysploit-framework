#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects exposure of MySQL credentials, configuration, and command history via HTTP."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'MySQL Conifg - Exposure Detection',
        'description': 'Detects exposure of MySQL credentials, configuration, and command history via HTTP. Exposure of files such as .my.cnf and .mysql_history may lead to leakage of database passwords or SQL history, enabling attackers to compromise databases.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'exposure', 'config', 'mysql', 'database'],
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
        'references': ['https://dev.mysql.com/doc/refman/8.0/en/option-files.html'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/.my.cnf', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('[client]',)
        body_regexes = ('password\\s*=\\s*["\']?[^"\'\\s]+["\']?',)
        if (any(m in body for m in body_any)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="MySQL Conifg - Exposure detected",
                path='/.my.cnf',
            )
            return True
        return False

