#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Enumerated Cisco UCM cluster nodes (servers) using the unauthenticated UDS API (XML), allowing identification ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Cisco Unified Communications Manager - Cluster Enumeration Detection',
        'description': 'Enumerated Cisco UCM cluster nodes (servers) using the unauthenticated UDS API (XML), allowing identification of backend servers without authentication.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'vulnerability', 'cisco', 'ucm', 'misconfig'],
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
            'https://developer.cisco.com/site/user-data-services/develop-and-test/api-reference/#servers',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/cucm-uds/servers', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        server = r.headers.get("Server") or r.headers.get("server") or ""
        body_all = ('<servers uri', '<server>',)
        header_any = ('text/xml', 'application/xml',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='low',
                reason="Cisco Unified Communications Manager - Cluster Enumeration detected",
                path='/cucm-uds/servers',
            )
            return True
        return False

