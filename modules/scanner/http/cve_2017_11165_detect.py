#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DataTaker DT80 dEX 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'DataTaker DT80 dEX 1.50.012 - Information Disclosure Detection',
        'description': 'DataTaker DT80 dEX 1.50.012 is susceptible to information disclosure. A remote attacker can obtain sensitive credential and configuration information via a direct request for the /services/getFile.cmd?userfile=config.xml URI, thereby possibly accessing sensitive information, modifying data, and/or executing unauthorized operations.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2017', 'lfr', 'edb', 'datataker', 'config', 'packetstorm', 'exposure', 'vuln'],
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
            'https://www.exploit-db.com/exploits/45094',
            'https://packetstormsecurity.com/files/143328/DataTaker-DT80-dEX-1.50.012-Sensitive-Configuration-Exposure.html',
            'https://www.exploit-db.com/exploits/42313/',
            'https://nvd.nist.gov/vuln/detail/CVE-2017-11165',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2017-11165',
    }

    def run(self):
        r = self.http_request(method="GET", path='/services/getFile.cmd?userfile=config.xml', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('COMMAND_SERVER', '<loggerSettings>', 'config id="config',)
        header_any = ('text/xml',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='critical',
                reason="DataTaker DT80 dEX 1.50.012 - Information Disclosure detected",
                path='/services/getFile.cmd?userfile=config.xml',
            )
            return True
        return False

