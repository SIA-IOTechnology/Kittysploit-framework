#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cobub Razor 0."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Cobub Razor 0.8.0 - Information Disclosure Detection',
        'description': 'Cobub Razor 0.8.0 is susceptible to information disclosure via generate.php, controllers/getConfigTest.php, controllers/getUpdateTest.php, controllers/postclientdataTest.php, controllers/posterrorTest.php, controllers/posteventTest.php, controllers/posttagTest.php, controllers/postusinglogTest.php, fixtures/Controller_fixt.php, fixtures/Controller_fixt2.php, fixtures/view_fixt2.php, libs/ipTest.php, or models/commonDbfix.php. An attacker can obtain sensitive information, modify data, and/or execute unauthorized operations.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'cobub', 'razor', 'exposure', 'edb', 'vuln'],
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
            'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-8770',
            'https://www.exploit-db.com/exploits/44495/',
            'https://github.com/Kyhvedn/CVE_Description/blob/master/Cobub_Razor_0.8.0_more_physical_path_leakage.md',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-8770',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2018-8770',
    }

    def run(self):
        r = self.http_request(method="GET", path='/tests/generate.php', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_all = ("Fatal error: Class 'PHPUnit_Framework_TestCase' not found in", '/application/third_party/CIUnit/libraries/CIUnitTestCase.php on line',)
        if (all(m in headers for m in header_all)):
            self.set_info(
                severity='medium',
                reason="Cobub Razor 0.8.0 - Information Disclosure detected",
                path='/tests/generate.php',
            )
            return True
        return False

