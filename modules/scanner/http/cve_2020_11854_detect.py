#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Micro Focus UCMDB is susceptible to remote code execution."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Micro Focus UCMDB - Remote Code Execution Detection',
        'description': 'Micro Focus UCMDB is susceptible to remote code execution. Impacted products include Operation Bridge Manager versions 2020.05, 2019.11, 2019.05, 2018.11, 2018.05, 10.63,10.62, 10.61, 10.60, 10.12, 10.11, 10.10 and all earlier versions, and Operations Bridge (containerized) 2020.05, 2019.08, 2019.05, 2018.11, 2018.08, 2018.05. 2018.02 and 2017.11. 3.), and Application Performance Management versions 9,51, 9.50 and 9.40 with UCMDB 10.33 CUP 3.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'microfocus', 'packetstorm', 'ucmdb', 'rce', 'vkev', 'vuln'],
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
            'http://packetstormsecurity.com/files/161182/Micro-Focus-UCMDB-Remote-Code-Execution.html',
            'https://softwaresupport.softwaregrp.com/doc/KM03747658',
            'https://softwaresupport.softwaregrp.com/doc/KM03747657',
            'https://softwaresupport.softwaregrp.com/doc/KM03747854',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-11854',
        ],
        'cve': 'CVE-2020-11854',
    }

    def run(self):
        r = self.http_request(method="GET", path='/ucmdb-api/connect', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('HttpUcmdbServiceProviderFactoryImpl', 'ServerVersion=11.6.0',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='critical',
                reason="Micro Focus UCMDB - Remote Code Execution detected",
                path='/ucmdb-api/connect',
            )
            return True
        return False

