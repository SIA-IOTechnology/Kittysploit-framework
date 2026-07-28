#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress WebP Converter for Media < 4."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress WebP Converter for Media < 4.0.3 - Unauthenticated Open Redirect Detection',
        'description': 'WordPress WebP Converter for Media < 4.0.3 contains a file (passthru.php) which does not validate the src parameter before redirecting the user to it, leading to an open redirect issue.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': [
            'web',
            'scanner',
            'cve',
            'cve2021',
            'redirect',
            'wp-plugin',
            'webpconverter',
            'wpscan',
            'wordpress',
            'webp_converter_for_media_project',
            'vuln',
        ],
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
            'https://wpscan.com/vulnerability/f3c0a155-9563-4533-97d4-03b9bac83164',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-25074',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2021-25074',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/plugins/webp-converter-for-media/includes/passthru.php?src=https://interact.sh', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?:\\/\\/|\\/\\/|\\/\\\\\\\\|\\/\\\\)(?:[a-zA-Z0-9\\-_\\.@]*)interact\\.sh\\/?(\\/|[^.].*)?$',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="WordPress WebP Converter for Media < 4.0.3 - Unauthenticated Open Redirect detected",
                path='/wp-content/plugins/webp-converter-for-media/includes/passthru.php?src=https://interact.sh',
            )
            return True
        return False

