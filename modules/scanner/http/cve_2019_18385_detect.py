#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TerraMaster NAS makecvs.php Event=http info disclosure (CVE-2019-18385)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'TerraMaster NAS - makecvs.php Info Disclosure (CVE-2019-18385)',
        'description': (
            'Detects CVE-2019-18385 by requesting /include/makecvs.php?Event=http and '
            'looking for Client-PORT / Client-IP headers in the response.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': [
            'web', 'scanner', 'cve', 'cve2019', 'terramaster', 'nas',
            'info-disclosure', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.2,
            'value': 0.8,
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
                    'scanner/http/cve_2020_28187_detect',
                    'scanner/http/cve_2020_15568_detect',
                ],
            },
        },
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2019-18385'],
        'cve': 'CVE-2019-18385',
    }

    def run(self):
        path = '/include/makecvs.php?Event=http'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ''
        headers = '\n'.join(f'{k}: {v}' for k, v in r.headers.items())
        blob = body + '\n' + headers
        if 'Client-PORT' in blob and 'Client-IP' in blob:
            self.set_info(
                severity='medium',
                reason='TerraMaster makecvs.php info disclosure (CVE-2019-18385)',
                path=path,
            )
            return True
        return False
