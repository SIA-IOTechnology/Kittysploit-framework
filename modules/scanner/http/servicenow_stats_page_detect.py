#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects exposed ServiceNow statistics pages (stats."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ServiceNow Stats Page - Detection',
        'description': 'Detects exposed ServiceNow statistics pages (stats.do) that reveal system information.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'misconfiguration', 'servicenow', 'exposure', 'misconfig'],
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
            'https://support.servicenow.com/kb?id=kb_article_view&sysparm_article=KB0517269',
            'https://www.servicenow.com/community/servicenow-ai-platform-forum/is-there-a-way-to-restrict-access-to-the-stats-do-page/m-p/1026919',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/stats.do', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        body_any = ('servlet statistics',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='info',
                reason="ServiceNow Stats Pageion detected",
                path='/stats.do',
            )
            return True
        return False

