#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Exposed PostgreSQL history files (."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'PostgreSQL History - Exposure Detection',
        'description': 'Exposed PostgreSQL history files (.psql_history) were detected. These files contain a record of executed SQL commands and may disclose sensitive information like passwords, database schemas, and query logic.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'exposure', 'postgres', 'config', 'history', 'database'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
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
        'references': ['https://www.postgresql.org/docs/current/app-psql.html#APP-PSQL-FILES'],
    }

    def run(self):
        for path in ('/.psql_history', '/psql_history', '/.postgresql_history'):
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = (r.text or "").lower()
            content_type = (r.headers.get("Content-Type") or r.headers.get("content-type") or "").lower()
            body_any = ('select * from', 'select * from', 'insert into', 'insert into', 'update', 'update',)
            body_all = ('select', 'from', 'where',)
            ctype_any = ('text/html',)
            body_regexes = ('(?m)^\\\\\\\\(q|h|\\\\?|g|d|dt|du|l|c|connect|copy)',)
            if (any(m in body for m in body_any)) and (all(m in body for m in body_all)) and (any(m in content_type for m in ctype_any)) and (any(re.search(rx, body, re.I) for rx in body_regexes)):
                self.set_info(
                    severity='low',
                    reason='PostgreSQL History - Exposure detected',
                    path=path,
                )
                return True
        return False

