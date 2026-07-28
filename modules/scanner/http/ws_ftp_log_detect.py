#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WS_FTP software, which is a popular FTP (File Transfer Protocol) client used for transferring files between a ."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WS FTP File Disclosure Detection',
        'description': 'WS_FTP software, which is a popular FTP (File Transfer Protocol) client used for transferring files between a local computer and a remote server has its log file exposed.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'exposure', 'ftp', 'logs', 'vuln'],
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
        for path in ('/ws_ftp.log', '/WS_FTP.LOG'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_regexes = ('\\d{4}\\.\\d{2}\\.\\d{2} \\d{2}:\\d{2} [A-Z] C:\\\\', '\\d{4}\\.\\d{2}\\.\\d{2} \\d{2}:\\d{2} [A-Z] D:\\\\',)
            if (any(re.search(rx, body, 0) for rx in body_regexes)):
                self.set_info(
                    severity='low',
                    reason="WS FTP File Disclosure detected",
                    path=path,
                )
                return True
        return False

