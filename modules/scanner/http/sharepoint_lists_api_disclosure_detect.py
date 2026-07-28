#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected exposed SharePoint lists-api endpoint without proper authentication, exposing site content and metada."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Microsoft SharePoint - List API Disclosure Detection',
        'description': 'Detected exposed SharePoint lists-api endpoint without proper authentication, exposing site content and metadata.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'technology', 'sharepoint', 'microsoft', 'exposure', 'misconfig'],
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
            'https://learn.microsoft.com/en-us/sharepoint/dev/sp-add-ins/working-with-lists-and-list-items-with-rest',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/_api/web/lists', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('TemplateFeatureId', 'd:ParentWebUrl', 'Web/Lists',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='low',
                reason="Microsoft SharePoint - List API Disclosure detected",
                path='/_api/web/lists',
            )
            return True
        return False

