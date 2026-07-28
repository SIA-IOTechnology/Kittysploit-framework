#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Open WebUI < 0."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Open WebUI < 0.9.5 - Information Disclosure Detection',
        'description': 'Open WebUI < 0.9.5 contains an information disclosure vulnerability caused by unauthenticated access to GET /api/v1/retrieval/ endpoint, letting remote attackers retrieve live RAG pipeline configuration without authorization, exploit requires no authentication.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2026', 'open-webui', 'exposure', 'misconfig'],
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
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': [
            'https://github.com/open-webui/open-webui/security/advisories/GHSA-65pg-qhhw-mxwg',
            'https://github.com/open-webui/open-webui',
            'https://nvd.nist.gov/vuln/detail/CVE-2026-45397',
        ],
        'cve': 'CVE-2026-45397',
    }

    def run(self):
        r = self.http_request(method="GET", path='/api/v1/retrieval/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('application/json',)
        body_all = ('CHUNK_SIZE', 'RAG_EMBEDDING_MODEL', 'RAG_TEMPLATE',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="Open WebUI < 0.9.5 - Information Disclosure detected",
                path='/api/v1/retrieval/',
            )
            return True
        return False

