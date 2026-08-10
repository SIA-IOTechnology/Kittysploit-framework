#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Magic AirMusic / TELESTAR internet radio missing access control (CVE-2019-13474)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Magic AirMusic - Unauth Control API Detection (CVE-2019-13474)',
        'description': (
            'Detects CVE-2019-13474 by requesting /playinfo, /hotkeylist or /stop and '
            'looking for XML result/menu responses without authentication.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': [
            'web', 'scanner', 'cve', 'cve2019', 'iot', 'airmusic', 'telestar',
            'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
            'value': 0.7,
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
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2019-13474'],
        'cve': 'CVE-2019-13474',
    }

    base_path = OptString('', 'Optional device base path', required=False)

    def _prefix(self) -> str:
        base = str(self.base_path or '').strip()
        if not base or base == '/':
            return ''
        if not base.startswith('/'):
            base = '/' + base
        return base.rstrip('/')

    def run(self):
        for cmd in ('playinfo', 'hotkeylist', 'stop'):
            path = f'{self._prefix()}/{cmd}'
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ''
            if (
                '<result>OK</result>' in body
                or '<menu><item_total>' in body
                or '<result>FAIL</result>' in body
            ):
                self.set_info(
                    severity='medium',
                    reason=f'Magic AirMusic unauth API via /{cmd} (CVE-2019-13474)',
                    path=path,
                )
                return True
        return False
