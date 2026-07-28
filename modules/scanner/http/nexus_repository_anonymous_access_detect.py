#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected Nexus Repository Manager instance with anonymous access enabled, allowing unauthenticated users to li."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Nexus Repository Manager - Anonymous Access Enabled Detection',
        'description': 'Detected Nexus Repository Manager instance with anonymous access enabled, allowing unauthenticated users to list and browse repositories containing private artifacts including source code, packages, and Docker images.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'misconfiguration', 'misconfig', 'nexus', 'sonatype', 'exposure', 'unauth'],
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
            'https://help.sonatype.com/en/anonymous-access.html',
            'https://help.sonatype.com/en/access-control.html',
        ],
    }

    def run(self):
        return False  # disabled: corrupted matchers
        r = self.http_request(method="GET", path='/service/rest/v1/repositories', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('maven', 'npm', 'docker', 'nuget', 'pypi', 'raw', 'apt', 'yum',)
        body_all = ()
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="Nexus Repository Manager - Anonymous Access Enabled detected",
                path='/service/rest/v1/repositories',
            )
            return True
        return False

