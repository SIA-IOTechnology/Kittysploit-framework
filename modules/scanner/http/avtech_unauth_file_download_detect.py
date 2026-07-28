#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AVTECH video surveillance products unauthenticated file download from web root through /cgi-bin/cgibox, Since ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'AVTECH Video Surveillance Product - Unauthenticated File Download Detection',
        'description': 'AVTECH video surveillance products unauthenticated file download from web root through /cgi-bin/cgibox, Since the .cab string is verified by the strstr method, the file download can be realized by adding ?.cab at the end of the file name.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'exposure', 'avtech', 'unauth', 'download', 'iot', 'vuln'],
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
        for path in ('/cgi-bin/cgibox?.cab', '/cgi-bin/cgibox?/nobody'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_all = ('ELF', 'ddns_avtech_final',)
            header_any = ('text/plain',)
            if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='high',
                    reason="AVTECH Video Surveillance Product - Unauthenticated File Download detected",
                    path=path,
                )
                return True
        return False

