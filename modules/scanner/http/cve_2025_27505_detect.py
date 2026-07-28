#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GeoServer contains a missing authorization vulnerability that allows unauthorized access to the REST API Index."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'GeoServer - Missing Authorization on REST API Index Detection',
        'description': 'GeoServer contains a missing authorization vulnerability that allows unauthorized access to the REST API Index page, potentially exposing sensitive configuration information.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'geoserver', 'misconfig', 'osgeo', 'vkev', 'vuln'],
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
            'http://geoserver.org/',
            'https://geoserver.org/vulnerability/2025/06/10/cve-disclosure.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-27505',
        ],
        'cve': 'CVE-2025-27505',
    }

    def run(self):
        for path in ('/rest.html', '/geoserver/rest.html'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('Geoserver Configuration API', 'about/status',)
            if (any(m in body for m in body_any)):
                self.set_info(
                    severity='medium',
                    reason="GeoServer - Missing Authorization on REST API Index detected",
                    path=path,
                )
                return True
        return False

