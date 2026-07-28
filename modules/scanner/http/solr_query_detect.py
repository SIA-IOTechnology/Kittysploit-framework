#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Solr's admin page was able to be accessed with no authentication requirements in place."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Solr - Admin Page Access Detection',
        'description': "Solr's admin page was able to be accessed with no authentication requirements in place.",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'misconfiguration', 'solr', 'unauth', 'edb', 'misconfig'],
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
        'references': ['https://www.exploit-db.com/ghdb/5856'],
    }

    def run(self):
        for path in ('/admin/', '/solr/admin/'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('<title>Solr admin page</title>',)
            if (any(m in body for m in body_any)):
                self.set_info(
                    severity='high',
                    reason="Solr - Admin Page Access detected",
                    path=path,
                )
                return True
        return False

