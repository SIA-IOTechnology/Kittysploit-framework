#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CouchDB is susceptible to requests in the context of an admin user."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'CouchDB Admin Default - Detect',
        'description': 'CouchDB is susceptible to requests in the context of an admin user.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'couchdb', 'vuln'],
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
        'references': ['https://docs.couchdb.org/en/stable/intro/security.html#authentication-database'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/_users/_all_docs', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('total_rows', 'offset',)
        header_all = ('CouchDB/', 'Erlang OTP/',)
        if (all(m in body for m in body_all)) and (all(m in headers for m in header_all)):
            self.set_info(
                severity='high',
                reason="CouchDB Admin Default detected",
                path='/_users/_all_docs',
            )
            return True
        return False

