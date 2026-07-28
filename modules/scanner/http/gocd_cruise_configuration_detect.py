#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GoCd Cruise Configuration is exposed."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'GoCd Cruise Configuration disclosure Detection',
        'description': 'GoCd Cruise Configuration is exposed.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'misconfiguration', 'go', 'gocd', 'config', 'exposure', 'misconfig', 'vuln'],
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
            'https://attackerkb.com/assessments/9101a539-4c6e-4638-a2ec-12080b7e3b50',
            'https://blog.sonarsource.com/gocd-pre-auth-pipeline-takeover',
            'https://twitter.com/wvuuuuuuuuuuuuu/status/1456316586831323140',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/go/add-on/business-continuity/api/cruise_config', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        server = r.headers.get("Server") or r.headers.get("server") or ""
        body_all = ('server agentAutoRegisterKey', 'webhookSecret', 'tokenGenerationKey',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="GoCd Cruise Configuration disclosure detected",
                path='/go/add-on/business-continuity/api/cruise_config',
            )
            return True
        return False

