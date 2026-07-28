#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Jetty showContexts is Enabled in DefaultHandler."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Jetty showContexts Enable in DefaultHandler Detection',
        'description': 'Jetty showContexts is Enabled in DefaultHandler',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'misconfiguration', 'jetty', 'misconfig', 'vuln'],
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
            'https://github.com/jaeles-project/jaeles-signatures/blob/master/common/jetty-showcontexts-enable.yaml',
            'https://swarm.ptsecurity.com/jetty-features-for-hacking-web-apps/',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=False)
        if not r or r.status_code != 404:
            return False
        body = r.text or ""
        server = r.headers.get("Server") or r.headers.get("server") or ""
        body_any = ('Contexts known to this server are:',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='low',
                reason="Jetty showContexts Enable in DefaultHandler detected",
                path='/',
            )
            return True
        return False

