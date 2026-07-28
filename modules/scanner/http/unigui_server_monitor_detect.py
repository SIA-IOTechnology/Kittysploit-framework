#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects exposed UniGUI Server Monitor Panels which could reveal sensitive server statistics, users sessions, l."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'UniGUI Server Monitor Panel - Exposure Detection',
        'description': 'Detects exposed UniGUI Server Monitor Panels which could reveal sensitive server statistics, users sessions, licensing information and others data.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'misconfiguration', 'exposure', 'unigui', 'misconfig', 'vuln'],
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
                'suggested_followups': [],
            },
        },
        'references': ['https://www.unigui.com/doc/online_help/using-server-monitor-(server-c.htm'],
    }

    def run(self):
        path = '/server'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('uniGUI Standalone Server', 'uniGUI License Information', 'Server Statistics',)
        if any(m in body for m in body_any):
            self.set_info(
                severity='low',
                reason='UniGUI Server Monitor Panel - Exposure detected',
                path=path,
            )
            return True
        return False

