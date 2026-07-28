#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Adiscon LogAnalyzer was discovered."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Adiscon LogAnalyzer - Information Disclosure Detection',
        'description': 'Adiscon LogAnalyzer was discovered. Adiscon LogAnalyzer is a web interface to syslog and other network event data. It provides easy browsing and analysis of real-time network events and reporting services.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'panel', 'adiscon', 'loganalyzer', 'syslog', 'exposure'],
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
        'references': ['https://loganalyzer.adiscon.com/'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_markers = (
            'Adiscon LogAnalyzer',
            'value="SYSLOG"',
            'value="EVTRPT"',
            'value="WEBLOG"',
        )
        body_hit = any(m in body for m in body_markers)
        if body_hit:
            self.set_info(
                severity='high',
                reason="Adiscon LogAnalyzer - Information Disclosure detected",
                path='/',
            )
            return True
        return False

