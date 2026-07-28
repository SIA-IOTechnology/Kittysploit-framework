#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Duplicator WordPress plugin before 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Duplicator < 1.5.7.1; Duplicator Pro < 4.5.14.2 - Unauthenticated Sensitive Data Exposure Detection',
        'description': 'The Duplicator WordPress plugin before 1.5.7.1, Duplicator Pro WordPress plugin before 4.5.14.2 does not disallow listing the `backups-dup-lite/tmp` directory (or the `backups-dup-pro/tmp` directory in the Pro version), which temporarily stores files containing sensitive data. When directory listing is enabled in the web server, this allows unauthenticated attackers to discover and access these sensitive files, which include a full database dump and a zip archive of the site.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web',
            'scanner',
            'cve',
            'cve2023',
            'duplicator',
            'duplicator-pro',
            'lfi',
            'wpscan',
            'wordpress',
            'wp-plugin',
            'wp',
            'awesomemotive',
            'vkev',
            'vuln',
        ],
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
            'https://drive.google.com/file/d/1mpapFCqfZLv__EAM7uivrrl2h55rpi1V/view?usp=sharing',
            'https://wpscan.com/vulnerability/5c5d41b9-1463-4a9b-862f-e9ee600ef8e1',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-6114',
            'https://wpscan.com/plugin/duplicator/',
        ],
        'cve': 'CVE-2023-6114',
    }

    def run(self):
        for path in ('/wp-content/backups-dup-lite/tmp/', '/wp-content/backups-dup-pro/tmp/'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('/tmp', '<title>Index of',)
            if (any(m in body for m in body_any)):
                self.set_info(
                    severity='high',
                    reason="Duplicator < 1.5.7.1; Duplicator Pro < 4.5.14.2 - Unauthenticated Sensitive Data Exposure detected",
                    path=path,
                )
                return True
        return False

