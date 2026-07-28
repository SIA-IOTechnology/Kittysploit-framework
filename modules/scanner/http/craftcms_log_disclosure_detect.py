#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected exposed Craft CMS log files due to misconfiguration, allowing unauthenticated access to sensitive inf."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Craft CMS - Log File Disclosure Detection',
        'description': 'Detected exposed Craft CMS log files due to misconfiguration, allowing unauthenticated access to sensitive information including error messages, stack traces, database queries, and potentially credentials or session data.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'exposure', 'craftcms', 'cms', 'logs', 'misconfig'],
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
            'https://craftcms.com/docs/5.x/system/logging.html',
            'https://craftcms.com/knowledge-base/locating-error-logs-and-database-backups',
            'https://github.com/craftcms/cms/issues/3619',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/storage/logs/web.log', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('craft_cms', 'UrlManager', 'schemaVersion',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="Craft CMS - Log File Disclosure detected",
                path='/storage/logs/web.log',
            )
            return True
        return False

