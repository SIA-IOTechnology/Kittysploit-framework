#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected exposed Jolokia configuration files (jolokia-agent."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Jolokia Configuration - Exposure Detection',
        'description': 'Detected exposed Jolokia configuration files (jolokia-agent.properties and jolokia-access.xml). Exposure of these files could have revealed sensitive agent configuration, authentication credentials, or access control policies (CORS, allowed MBeans).',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'exposure', 'config', 'jolokia', 'jmx', 'devops'],
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
        'references': [
            'https://jolokia.org/reference/html/agents.html',
            'https://docs.microfocus.com/doc/388/24.3/confjolokia',
        ],
    }

    def run(self):
        for path in ('/jolokia-agent.properties', '/jolokia-access.xml', '/WEB-INF/classes/jolokia-agent.properties', '/WEB-INF/classes/jolokia-access.xml'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('host=', 'port=', 'protocol=', 'password=', '<restrict>', '<remote>', '<host>', '<mbean>',)
            if (all(m in body for m in body_all)):
                self.set_info(
                    severity='medium',
                    reason="Jolokia Configuration - Exposure detected",
                    path=path,
                )
                return True
        return False

