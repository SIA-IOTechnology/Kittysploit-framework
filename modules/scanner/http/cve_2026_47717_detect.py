#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FUXA v1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'FUXA 1.3.0 - Unauthenticated ICS/SCADA Project Data Disclosure Detection',
        'description': 'FUXA v1.3.0 exposes full SCADA/HMI project configuration via GET /api/project without authentication, even when secureEnabled is true. The secureFnc middleware auto-generates a valid guest JWT when no token is provided, bypassing authentication. Exposed data includes server-side scripts, device configs, HMI views, and alarm definitions.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2026', 'fuxa', 'ics', 'scada', 'unauth', 'exposure'],
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
            'https://github.com/advisories/GHSA-q3w6-q3hc-c5x6',
            'https://www.miggo.io/vulnerability-database/cve/CVE-2026-47717',
        ],
        'cve': 'CVE-2026-47717',
    }

    def run(self):
        r = self.http_request(method="GET", path='/api/project', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('devices', 'hmi', 'alarms', 'views', 'variables',)
        body_all = ('scripts', 'id',)
        header_any = ('application/json',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="FUXA 1.3.0 - Unauthenticated ICS/SCADA Project Data Disclosure detected",
                path='/api/project',
            )
            return True
        return False

