#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""In WS_FTP Server versions prior to 8."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WS_FTP Server - Insecure Deserialization Detection',
        'description': 'In WS_FTP Server versions prior to 8.7.4 and 8.8.2, a pre-authenticated attacker could leverage a .NET deserialization vulnerability in the Ad Hoc Transfer module to execute remote commands on the underlying WS_FTP Server operating system.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'ws_ftp', 'kev', 'passive', 'vkev'],
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
            'https://attackerkb.com/topics/bn32f9sNax/cve-2023-40044',
            'https://censys.com/cve-2023-40044/',
            'https://www.progress.com/ws_ftp',
            'https://www.rapid7.com/blog/post/2023/09/29/etr-critical-vulnerabilities-in-ws_ftp-server/',
            'https://www.theregister.com/2023/10/02/ws_ftp_update/',
        ],
        'cve': 'CVE-2023-40044',
    }

    def run(self):
        r = self.http_request(method="GET", path='/AHT/AHT_UI/public/js/app.min.js', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('/\\*! fileTransfer \\d+-(0[1-9]|1[0-2])-(19\\d{2}|20[01]\\d|202[0-2]) \\*/', '/\\*! fileTransfer \\d+-(0[1-8])-2023 \\*/',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='critical',
                reason="WS_FTP Server - Insecure Deserialization detected",
                path='/AHT/AHT_UI/public/js/app.min.js',
            )
            return True
        return False

