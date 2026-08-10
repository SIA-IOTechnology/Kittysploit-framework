#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Enumerate allowed HTTP methods (OPTIONS Allow header + active probes)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


RISKY_METHODS = ('PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH')
BASIC_METHODS = ('GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE')


class Module(Scanner, Http_client):

    __info__ = {
        'name': 'HTTP Methods Enumeration',
        'description': (
            'Enumerates allowed HTTP methods via OPTIONS Allow header and active probes '
            'of basic methods. Flags risky methods (PUT/DELETE/TRACE/CONNECT/PATCH).'
        ),
        'author': ['KittySploit Team'],
        'severity': 'info',
        'modules': [],
        'tags': ['web', 'scanner', 'http', 'methods', 'options', 'allow', 'misconfig'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 10,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.6,
            'value': 0.7,
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
                'produces_capabilities': [{'capability': 'admin_surface', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
    }

    def run(self):
        allowed = set()

        r = self.http_request(method='OPTIONS', path='/', allow_redirects=False)
        if r:
            allow = r.headers.get('Allow') or r.headers.get('allow') or ''
            for m in allow.split(','):
                name = m.strip().upper()
                if name:
                    allowed.add(name)
            # OPTIONS itself worked
            if r.status_code not in (405, 501):
                allowed.add('OPTIONS')

        # Active probes when Allow header is missing/incomplete (NASL-style)
        if len(allowed) < 2:
            # Baseline: send nonsense method to learn error shape
            junk = self.http_request(method='KITTYSPLOIT', path='/', allow_redirects=False)
            junk_code = junk.status_code if junk else None
            for method in BASIC_METHODS:
                if method in allowed:
                    continue
                pr = self.http_request(method=method, path='/', allow_redirects=False)
                if not pr:
                    continue
                # Method allowed if not method-not-allowed and not same hard-fail as junk
                if pr.status_code in (405, 501):
                    continue
                if (
                    junk_code is not None
                    and pr.status_code == junk_code
                    and pr.status_code >= 400
                ):
                    continue
                allowed.add(method)

        if not allowed:
            return False

        methods = sorted(allowed)
        risky = [m for m in methods if m in RISKY_METHODS]
        if risky:
            self.set_info(
                severity='low',
                reason=f"Allowed: {', '.join(methods)} (risky: {', '.join(risky)})",
                methods=methods,
                risky_methods=risky,
            )
        else:
            self.set_info(
                severity='info',
                reason=f"Allowed methods: {', '.join(methods)}",
                methods=methods,
            )
        return True
