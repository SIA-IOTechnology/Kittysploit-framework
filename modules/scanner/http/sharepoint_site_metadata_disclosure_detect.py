#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected exposed SharePoint site metadata endpoints."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Microsoft SharePoint - Site Metadata Disclosure Detection',
        'description': 'Detected exposed SharePoint site metadata endpoints.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'misconfiguration', 'sharepoint', 'microsoft', 'exposure', 'misconfig'],
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
        'references': [
            'https://learn.microsoft.com/en-us/sharepoint/dev/sp-add-ins/get-to-know-the-sharepoint-rest-service',
            'https://medium.com/@ujmalhotra95/tales-of-sharepoint-api-misconfigurations-11073ad384fd',
        ],
    }

    def run(self):
        for path in ('/_api/site', '/_api/web'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('__metadata', 'WelcomePage', 'ServerRelativeUrl', 'Upgrading',)
            if (all(m in body for m in body_all)):
                self.set_info(
                    severity='low',
                    reason="Microsoft SharePoint - Site Metadata Disclosure detected",
                    path=path,
                )
                return True
        return False

