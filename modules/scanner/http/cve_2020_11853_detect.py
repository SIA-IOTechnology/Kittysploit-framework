#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Micro Focus Operations Bridge Manager in versions 2020."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Micro Focus Operations Bridge Manager <=2020.05 - Remote Code Execution Detection',
        'description': 'Micro Focus Operations Bridge Manager in versions 2020.05 and below is vulnerable to remote code execution via UCMDB. The vulnerability allows remote attackers to execute arbitrary code on affected installations of Data Center Automation. An attack requires network access and authentication as a valid application user. Originated from Metasploit module (#14654).',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'opm', 'rce', 'packetstorm', 'microfocus', 'vuln'],
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
            'http://packetstormsecurity.com/files/161366/Micro-Focus-Operations-Bridge-Manager-Remote-Code-Execution.html',
            'https://softwaresupport.softwaregrp.com/doc/KM03747658',
            'https://softwaresupport.softwaregrp.com/doc/KM03747949',
            'https://softwaresupport.softwaregrp.com/doc/KM03747948',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-11853',
        ],
        'cve': 'CVE-2020-11853',
    }

    def run(self):
        r = self.http_request(method="GET", path='/ucmdb-api/connect', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('HttpUcmdbServiceProviderFactoryImpl', 'ServerVersion=11.6.0',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="Micro Focus Operations Bridge Manager <=2020.05 - Remote Code Execution detected",
                path='/ucmdb-api/connect',
            )
            return True
        return False

