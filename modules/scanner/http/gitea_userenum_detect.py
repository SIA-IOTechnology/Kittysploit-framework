#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Enumerates the users registered in the Gitea web application, a self-hosted all-in-one software development se."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Gitea - User Enumeration Detection',
        'description': 'Enumerates the users registered in the Gitea web application, a self-hosted all-in-one software development service, including Git hosting, code review, team collaboration, package registry and CI/CD.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'misconfiguration', 'tech', 'gitea', 'enumeration'],
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
    }

    def run(self):
        r = self.http_request(method="GET", path='/explore/users/sitemap-1.xml', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('/schemas/sitemap/', 'lastmod',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='low',
                reason="Gitea - User Enumeration detected",
                path='/explore/users/sitemap-1.xml',
            )
            return True
        return False

