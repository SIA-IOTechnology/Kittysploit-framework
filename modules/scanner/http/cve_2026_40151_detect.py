#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PraisonAI's AgentOS FastAPI application server exposes an unauthenticated `GET /api/agents` endpoint that list."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'PraisonAI AgentOS - Information Disclosure Detection',
        'description': "PraisonAI's AgentOS FastAPI application server exposes an unauthenticated `GET /api/agents` endpoint that lists every registered agent's name, role and the opening of its instructions (system prompt). No authentication is enforced on the route, allowing a remote attacker to enumerate agent configurations and harvest sensitive details embedded in system prompts, such as internal API references, business logic and credential hints. This endpoint belongs to the AgentOS FastAPI server and is distinct from the legacy Flask `/agents` server tracked as CVE-2026-44338.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2026', 'praisonai', 'praison', 'exposure'],
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
            'https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-pm96-6xpr-978x',
            'https://nvd.nist.gov/vuln/detail/CVE-2026-40151',
        ],
        'cve': 'CVE-2026-40151',
    }

    def run(self):
        r = self.http_request(method="GET", path='/api/agents', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('"agents"', '"role"', '"instructions"',)
        header_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="PraisonAI AgentOS - Information Disclosure detected",
                path='/api/agents',
            )
            return True
        return False

