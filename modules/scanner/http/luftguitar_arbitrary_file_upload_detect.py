#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A vulnerability in Luftguitar CMS allows remote unauthenticated users to upload files to the remote service vi."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Luftguitar CMS Arbitrary File Upload Detection',
        'description': "A vulnerability in Luftguitar CMS allows remote unauthenticated users to upload files to the remote service via the 'ftb.imagegallery.aspx' endpoint.",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'luftguitar', 'edb', 'vuln'],
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
        'references': ['https://www.exploit-db.com/exploits/14991'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/ftb.imagegallery.aspx', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('<title>Insert Image</title>', '<title>Image Gallery</title>',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='high',
                reason="Luftguitar CMS Arbitrary File Upload detected",
                path='/ftb.imagegallery.aspx',
            )
            return True
        return False

