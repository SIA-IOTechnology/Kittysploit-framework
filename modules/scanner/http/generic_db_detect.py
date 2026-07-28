#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""This is collection of some web frameworks recommendation or default configuration for SQLite database file loc."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Generic Database File - Exposure Detection',
        'description': 'This is collection of some web frameworks recommendation or default configuration for SQLite database file location. If this file is publicly accessible due to server misconfiguration, it could result in application data leak including users sensitive data, password hashes etc.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'exposure', 'files', 'database', 'sqlite', 'sqlite3', 'fuzz', 'sqli', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 6,
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
        'references': [
            'https://laravel.com/docs/11.x/database#sqlite-configuration',
            'https://laravel.com/docs/5.2/database',
            'https://github.com/laracasts/larabook/blob/master/app/config/database.php#L51',
            'https://forum.codeigniter.com/post-389846.html',
            'https://github.com/codeigniter4projects/playground/blob/develop/.env.example#L33',
        ],
    }

    def run(self):
        for path in ('/database/database.sqlite', '/database/production.db', '/database/production.sqlite', '/database/production.sqlite3', '/app/database/production.sqlite', '/writable/db.sqlite3', '/writable/database.db', '/var/app.db'):
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('CREATE TABLE', '<html',)
            if any(m in body for m in body_any):
                self.set_info(
                    severity='high',
                    reason='Generic Database File - Exposure detected',
                    path=path,
                )
                return True
        return False

