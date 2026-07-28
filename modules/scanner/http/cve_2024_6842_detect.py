#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AnythingLLM suffers from an information disclosure vulnerability through the `/api/setup-complete` API endpoin."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'AnythingLLM - Information Disclosure Detection',
        'description': 'AnythingLLM suffers from an information disclosure vulnerability through the `/api/setup-complete` API endpoint. By accessing this endpoint, a remote and unauthenticated attacker can access sensitive configuration of the target AnythingLLM instance. This detection is included in the AI and LLM category.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'unauth', 'exposure', 'anything-llm', 'mintplex-labs', 'vuln', 'ai'],
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
            'https://huntr.com/bounties/cd911fc7-ac6b-4974-acd0-9cc926fa8d9e',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-6842',
        ],
        'cve': 'CVE-2024-6842',
    }

    def run(self):
        r = self.http_request(method="GET", path='/api/setup-complete', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('"AgentGoogleSearchEngineId":', '-"AgentGoogleSearchEngineKey":\'', '"AgentSerperApiKey":', '"AgentBingSearchApiKey":',)
        body_all = ('AuthToken\\', ':true')
        header_any = ('application/json',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="AnythingLLM - Information Disclosure detected",
                path='/api/setup-complete',
            )
            return True
        return False

