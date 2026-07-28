#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected an exposed ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Perforce Repository Disclosure Detection',
        'description': 'Detected an exposed .p4ignore file, which could have revealed ignored files, sensitive paths, or developer-specific information useful for further enumeration.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'misconfiguration', 'exposure', 'perforce', 'repo', 'disclosure'],
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
            'https://help.perforce.com/helix-core/server-apps/cmdref/current/Content/CmdRef/P4IGNORE.html',
        ],
    }

    def run(self):
        path = '/.p4ignore'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        content_type = (r.headers.get("Content-Type") or r.headers.get("content-type") or "").lower()
        body_any = ('*.log', 'yarn-error.log', '<html', '<body', '<!doctype',)
        ctype_any = ('application/octet-stream',)
        if (any(m in body for m in body_any)) and (any(m in content_type for m in ctype_any)):
            self.set_info(
                severity='low',
                reason='Perforce Repository Disclosure detected',
                path=path,
            )
            return True
        return False

