#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Weblate instance is publicly accessible."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Weblate Public Project - Exposure Detection',
        'description': 'Weblate instance is publicly accessible. Public exposure of Weblate may lead to unauthorized access to translation projects, potential data leaks, credential exposure, or manipulation of open source localization data. Attackers can view available projects and access sensitive information if proper access controls are not implemented.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'misconfiguration', 'misconfig', 'exposure', 'weblate', 'public'],
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
            'https://docs.weblate.org/en/latest/admin/security.html',
            'https://github.com/WeblateOrg/weblate',
        ],
    }

    def run(self):
        path = '/projects/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        body_all = ('Weblate', 'Untranslated', 'Browse all projects',)
        ctype_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in content_type for m in ctype_any)):
            self.set_info(
                severity='info',
                reason='Weblate Public Project - Exposure detected',
                path=path,
            )
            return True
        return False

