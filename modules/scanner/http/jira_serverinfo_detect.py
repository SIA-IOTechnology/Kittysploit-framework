#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected Jira REST API serverInfo endpoint is accessible without authentication, exposing sensitive server inf."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Jira Rest API Server Information Detection',
        'description': 'Detected Jira REST API serverInfo endpoint is accessible without authentication, exposing sensitive server information including version, build number, server title, base URL, and server time.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'technology', 'jira', 'tech'],
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
            'https://developer.atlassian.com/cloud/jira/platform/rest/v2/api-group-server-info/',
            'https://support.atlassian.com/jira/kb/restrict-unauthenticated-access-for-some-jira-endpoints/',
        ],
    }

    def run(self):
        for path in ('/rest/api/latest/serverInfo', '/rest/api/2/serverInfo'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_markers = ('"baseUrl"', '"deploymentType"',)
            if any(m in body for m in body_markers):
                self.set_info(
                    severity='info',
                    reason="Jira Rest API Server Information detected",
                    path=path,
                )
                return True
        return False

