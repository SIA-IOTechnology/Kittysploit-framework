#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Webnus Inc."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Webnus Inc. Modern Events Calendar - Broken Access Control Detection',
        'description': 'Webnus Inc. Modern Events Calendar <= 7.29.0 contains a broken access control vulnerability caused by incorrectly configured access control security levels, letting attackers bypass authorization, exploit requires no special privileges.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve2026', 'cve', 'wordpress', 'wp-plugin', 'wp', 'mec', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2026-32583'],
        'cve': 'CVE-2026-32583',
    }

    def run(self):
        path = '/wp-admin/admin-ajax.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='action=mec_speaker_adding\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('mec_fes_speakers',)
        if any(m in body for m in body_any):
            self.set_info(severity='medium', reason='Webnus Inc. Modern Events Calendar - Broken Access Control detected', path=path)
            return True
        return False

