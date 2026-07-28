#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tenable Nessus panel was detected."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Tenable Nessus Panel - Detect',
        'description': 'Tenable Nessus panel was detected.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'nessus', 'tenable'],
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
    }

    def run(self):
        for path in ('/', '/server/status'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_markers = (
                '<title>Nessus</title>',
                "window.location = '/unsupported6.html';",
            )
            body_hit = any(m in body for m in body_markers)
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            header_markers = (
                'NessusWWW',
            )
            if body_hit and any(m in headers for m in header_markers):
                self.set_info(
                    severity='info',
                    reason="Tenable Nessus Panel detected",
                    path=path,
                )
                return True
        return False

