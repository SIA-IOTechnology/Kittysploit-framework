#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Deteted information revealed that Microsoft SharePoint files had been inadvertently disclosed."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Microsoft SharePoint Files Disclosure Detection',
        'description': 'Deteted information revealed that Microsoft SharePoint files had been inadvertently disclosed.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'misconfiguration', 'sharepoint', 'microsoft', 'exposure', 'misconfig'],
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
            'https://sharepointstuff.com/2021/03/30/useful-sharepoint-urls/',
            'https://docs.microsoft.com/en-us/sharepoint/dev/sp-add-ins/working-with-folders-and-files-with-rest',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/_api/web/roledefinitions', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('BasePermissions', 'schemas.microsoft.com', '_api/Web/',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='info',
                reason="Microsoft SharePoint Files Disclosure detected",
                path='/_api/web/roledefinitions',
            )
            return True
        return False

