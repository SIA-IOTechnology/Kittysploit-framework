#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Allegro RomPager Misfortune Cookie (CVE-2014-9222)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'RomPager - Misfortune Cookie Detection (CVE-2014-9222)',
        'description': (
            'Detects CVE-2014-9222 by sending Cookie C107373883=/<token> to /tr069 '
            'and matching the token plus RomPager not-found marker.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2014', 'rompager', 'iot', 'auth-bypass', 'unauth', 'kev', 'vuln',
        ],
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
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'admin_surface', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2014-9222',
            'https://mis.fortunecook.ie/',
        ],
        'cve': 'CVE-2014-9222',
    }

    def run(self):
        token = '/' + self.random_text(10)
        r = self.http_request(
            method='GET',
            path='/tr069',
            headers={'Cookie': f'C107373883={token}'},
            allow_redirects=False,
        )
        if not r:
            return False
        body = r.text or ''
        if token in body and 'was not found on the RomPager' in body:
            self.set_info(
                severity='critical',
                reason='RomPager Misfortune Cookie (CVE-2014-9222)',
                path='/tr069',
            )
            return True
        return False
