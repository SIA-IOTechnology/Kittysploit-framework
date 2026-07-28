#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Prodigy, a commercial scriptable annotation tool by Explosion AI used to label training data for machine learn."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Prodigy Annotation Tool - Unauthenticated Exposure Detection',
        'description': 'Prodigy, a commercial scriptable annotation tool by Explosion AI used to label training data for machine learning and NLP models, was detected. Its local web server (default port 8080, built on uvicorn/FastAPI) ships with no built-in authentication or user accounts by default and is designed to run on localhost or a trusted network. The annotation UI was found directly reachable to unauthenticated visitors.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'panel', 'prodigy', 'ai', 'data-annotation', 'misconfig', 'exposure'],
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
        'references': ['https://prodi.gy', 'https://prodi.gy/docs'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_markers = (
            '<title>Prodigy</title>',
            'id="root"',
            'src="bundle.js"',
        )
        body_hit = any(m in body for m in body_markers)
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_markers = (
            'uvicorn',
        )
        if body_hit and any(m in headers for m in header_markers):
            self.set_info(
                severity='medium',
                reason="Prodigy Annotation Tool - Unauthenticated Exposure detected",
                path='/',
            )
            return True
        return False

