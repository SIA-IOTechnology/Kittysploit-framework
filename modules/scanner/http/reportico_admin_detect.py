#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Create a simple report using the designer front end in seconds from a single SQL statement."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Reportico Administration Page - Detect',
        'description': 'Create a simple report using the designer front end in seconds from a single SQL statement. Add expressions, user criteria, charts, groups, aggregations, page headers, page footers, hyperlinks and even custom plugin code.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'reportico', 'login'],
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
        'references': ['https://www.reportico.org/site2/index.php', 'https://github.com/reportico-web/reportico'],
    }

    def run(self):
        markers = (
            'Reportico Administration',
            'reportico_',
        )
        for path in ('/run.php?project=admin&execute_mode=ADMIN&clear_session=1', '/reportico/run.php?project=admin&execute_mode=ADMIN&clear_session=1'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = (r.text or "")
            if any(m in body for m in markers):
                self.set_info(
                    severity='info',
                    reason="Reportico Administration Page detected",
                    path=path,
                )
                return True
        return False

