#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Fancy Product Designer plugin before 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Fancy Product Designer <4.6.9 - Arbitrary File Upload Detection',
        'description': 'WordPress Fancy Product Designer plugin before 4.6.9 is susceptible to an arbitrary file upload. An attacker can upload malicious files and execute code on the server, modify data, and/or gain full control over a compromised system without authentication.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'wordpress', 'wp', 'seclists', 'wpscan', 'rce', 'wp-plugin', 'fancyproduct', 'radykal', 'vkev', 'vuln'],
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
            'https://www.wordfence.com/blog/2021/06/critical-0-day-in-fancy-product-designer-under-active-attack/',
            'https://wpscan.com/vulnerability/82c52461-1fdc-41e4-9f51-f9dd84962b38',
            'https://seclists.org/fulldisclosure/2020/Nov/30',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-24370',
            'https://www.secpod.com/blog/critical-zero-day-flaw-actively-exploited-in-wordpress-fancy-product-designer-plugin/',
        ],
        'cve': 'CVE-2021-24370',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/plugins/fancy-product-designer/inc/custom-image-handler.php', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('{"error":"You need to define a directory',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='critical',
                reason="WordPress Fancy Product Designer <4.6.9 - Arbitrary File Upload detected",
                path='/wp-content/plugins/fancy-product-designer/inc/custom-image-handler.php',
            )
            return True
        return False

