#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected exposure of build information in JFrog Artifactory via unauthenticated API endpoints."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'JFrog Artifactory Build - Exposure Detection',
        'description': 'Detected exposure of build information in JFrog Artifactory via unauthenticated API endpoints. Access to these endpoints may disclose sensitive data such as build names, numbers, CI/CD pipeline details, artifact paths, and internal infrastructure information.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'exposure', 'jfrog', 'artifactory', 'misconfig', 'cicd'],
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
        'references': ['https://jfrog.com/help/r/jfrog-rest-apis/builds', 'https://jfrog.com/artifactory/'],
    }

    def run(self):
        path = '/artifactory/api/build'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        body_all = ('"builds"', '"uri"', '"lastStarted"',)
        ctype_any = ('application/json', 'application/vnd.org.jfrog',)
        if (all(m in body for m in body_all)) and (any(m in content_type for m in ctype_any)):
            self.set_info(
                severity='medium',
                reason='JFrog Artifactory Build - Exposure detected',
                path=path,
            )
            return True
        return False

