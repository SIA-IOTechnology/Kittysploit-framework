#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Download Monitor plugin for WordPress is vulnerable to Sensitive Information Exposure in versions up to, a."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Download Monitor <= 4.7.60 - Sensitive Information Exposure Detection',
        'description': 'The Download Monitor plugin for WordPress is vulnerable to Sensitive Information Exposure in versions up to, and including, 4.7.60 via REST API. This can allow unauthenticated attackers to extract sensitive data including user reports, download reports, and user data including email, role, id and other info (not passwords)',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'wordpress', 'wp-plugin', 'download-monitor', 'wp', 'wpchill', 'vkev', 'vuln'],
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
            'https://github.com/RandomRobbieBF/CVE-2022-45354',
            'https://wordpress.org/plugins/download-monitor/',
            'https://patchstack.com/database/vulnerability/download-monitor/wordpress-download-monitor-plugin-4-7-60-sensitive-data-exposure-vulnerability?_s_id=cve',
            'https://github.com/nomi-sec/PoC-in-GitHub',
        ],
        'cve': 'CVE-2022-45354',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-json/download-monitor/v1/user_data', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('"registered":', '"display_name":',)
        header_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="Download Monitor <= 4.7.60 - Sensitive Information Exposure detected",
                path='/wp-json/download-monitor/v1/user_data',
            )
            return True
        return False

