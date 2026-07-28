#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SolarWinds Web Help Desk was found to be susceptible to a security control bypass vulnerability that if exploi."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SolarWinds Web Help Desk < 12.8.8 Hotfix 1 (HF1) - Security Control Bypass Detection',
        'description': 'SolarWinds Web Help Desk was found to be susceptible to a security control bypass vulnerability that if exploited, could allow an unauthenticated attacker to gain access to certain restricted functionality.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'solarwinds', 'webhelpdesk', 'kev', 'vkev', 'passive'],
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
            'https://www.solarwinds.com/trust-center/security-advisories/cve-2025-40536',
            'https://documentation.solarwinds.com/en/success_center/whd/content/release_notes/whd_2026-1_release_notes.htm',
            'https://horizon3.ai/attack-research/cve-2025-40551-another-solarwinds-web-help-desk-deserialization-issue/',
        ],
        'cve': 'CVE-2025-40536',
    }

    def run(self):
        path = '/helpdesk/WebObjects/Helpdesk.woa'
        r = self.http_request(method='GET', path=path, allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Web Help Desk Software', 'SolarWinds WorldWide', '/WebObjects/Helpdesk.woa',)
        if any(m in body for m in body_any):
            self.set_info(
                severity='high',
                reason='SolarWinds Web Help Desk < 12.8.8 Hotfix 1 (HF1) - Security Control Bypass detected',
                path=path,
            )
            return True
        return False

