#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""BlueImp jQuery-File-Upload does not require validation to upload files to the server and does not exclude file."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'BlueImp jQuery-File-Upload - Arbitrary File Upload Detection',
        'description': 'BlueImp jQuery-File-Upload does not require validation to upload files to the server and does not exclude file types, which can lead to a remote code execution vulnerability.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'misconfiguration', 'exposure', 'jquery', 'edb', 'misconfig', 'vuln'],
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
            'https://www.exploit-db.com/exploits/45584',
            'https://github.com/blueimp/jQuery-File-Upload/blob/master/server/php/UploadHandler.php',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/jquery-file-upload/server/php/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        server = r.headers.get("Server") or r.headers.get("server") or ""
        header_any = ('text/plain',)
        body_regexes = ('^{\\"files\\":',)
        if (any(m in headers for m in header_any)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='critical',
                reason="BlueImp jQuery-File-Upload - Arbitrary File Upload detected",
                path='/jquery-file-upload/server/php/',
            )
            return True
        return False

