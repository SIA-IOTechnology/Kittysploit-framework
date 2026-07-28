#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Grafana through 7."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Grafana & Zabbix Integration - Credentials Disclosure Detection',
        'description': 'Grafana through 7.3.4, when integrated with Zabbix, contains a credential disclosure vulnerability. The Zabbix password can be found in the api_jsonrpc.php HTML source code. When the user logs in and allows the user to register, one can right click to view the source code and use Ctrl-F to search for password in api_jsonrpc.php to discover the Zabbix account password and URL address.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'grafana', 'zabbix', 'exposure', 'vuln'],
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
            'https://2k8.org/post-319.html',
            'https://security.netapp.com/advisory/ntap-20220425-0005/',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-26148',
            'https://github.com/HimmelAward/Goby_POC',
            'https://github.com/Z0fhack/Goby_POC',
        ],
        'cve': 'CVE-2022-26148',
    }

    def run(self):
        r = self.http_request(method="GET", path='/login?redirect=%2F', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('"zabbix":', '"zbx":', 'alexanderzobnin-zabbix-datasource',)
        body_regexes = ('"password":"(.*?)"', '"username":"(.*?)"',)
        if (any(m in body for m in body_any)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='critical',
                reason="Grafana & Zabbix Integration - Credentials Disclosure detected",
                path='/login?redirect=%2F',
            )
            return True
        return False

